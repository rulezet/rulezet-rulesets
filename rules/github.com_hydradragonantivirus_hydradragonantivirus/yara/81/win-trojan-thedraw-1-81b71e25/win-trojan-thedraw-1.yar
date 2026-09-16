rule Win_Trojan_TheDraw_1
{
strings:
	$a0 = { 4ebae212cd21b8023dba9e00cd21b74093ba0001b98219cd21e89a02b44ebae812cd21 }


condition:
	$a0
}