rule Win_Trojan_Cha_2
{
strings:
	$a0 = { 515257561e06e800005d83ed0b2e89ae0d052e8c860f058cc88ec08d9ec605b80102ba8000b90400cd13b855552e }


condition:
	$a0
}