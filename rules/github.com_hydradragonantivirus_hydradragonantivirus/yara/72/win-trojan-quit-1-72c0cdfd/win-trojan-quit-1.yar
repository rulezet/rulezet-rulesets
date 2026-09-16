rule Win_Trojan_Quit_1
{
strings:
	$a0 = { 5d83ed31b8f130cd218cdb0ac074464b }


condition:
	$a0
}