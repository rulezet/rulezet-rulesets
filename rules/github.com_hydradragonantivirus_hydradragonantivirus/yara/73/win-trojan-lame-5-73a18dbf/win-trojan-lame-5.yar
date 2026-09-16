rule Win_Trojan_Lame_5
{
strings:
	$a0 = { 0e1febc2ba740cb409cd21eb00b419cd218ad0b405b009bbee0b0e07b500b101b600cd13cd20 }


condition:
	$a0
}