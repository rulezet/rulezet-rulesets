rule Win_Trojan_Small_4558
{
strings:
	$a0 = { 81c0c9d7420068435304006822749800 }


condition:
	$a0
}