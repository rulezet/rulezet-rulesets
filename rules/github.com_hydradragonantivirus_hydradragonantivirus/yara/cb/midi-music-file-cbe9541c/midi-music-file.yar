import "pe"
rule _MIDI_Music_file_
{
	meta:
		description = "MIDI Music file"
	strings:
		$0 = {4D 54 68 64 00 00 00 06 ?? ?? ?? ?? ?? ?? 4D 54}
	condition:
		$0 at pe.entry_point
}