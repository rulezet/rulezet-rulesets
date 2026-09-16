rule Win_Trojan_Mini_35
{
strings:
	$a0 = { 77302d0300bf780003fd8805886501b80042cd21b440ba770003d5b90500cd21b8024233d2 }


condition:
	$a0
}