rule _VBOX_v43__v46_
{
	meta:
		description = "VBOX v4.3 - v4.6"
	strings:
		$0 = {8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5}
		$1 = {90 03 C4 33 C4 33 C5 2B C5 33 C5 8B C5 ?? ?? 2B C5 48 ?? ?? 0B C0 86 E0 8C E0 ?? ?? 8C E0 86 E0 03 C4 40}
	condition:
		$0 or $1
}