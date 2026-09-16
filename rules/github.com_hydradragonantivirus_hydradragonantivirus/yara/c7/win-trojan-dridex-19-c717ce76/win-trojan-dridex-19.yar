rule Win_Trojan_Dridex_19
{
strings:
	$a0 = { 31D28B??24??000000F7[0-32]8B8424[16-64]0FB60?[0-32]0FB6 }

	$a1 = { 5F63686B73746B }


condition:
	$a0 and $a1
}