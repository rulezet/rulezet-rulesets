rule PEiD_01133_MIDI_Music_file_ {
  meta:
    description = "[MIDI Music file]"
    ep_only     = "false"

  strings:
    $a = { 4D 54 68 64 00 00 00 06 ?? ?? ?? ?? ?? ?? 4D 54 }

  condition:
    $a
}