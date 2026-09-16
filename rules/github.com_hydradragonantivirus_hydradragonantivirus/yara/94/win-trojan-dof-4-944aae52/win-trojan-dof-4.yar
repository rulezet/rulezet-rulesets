rule Win_Trojan_Dof_4
{
strings:
	$a0 = { 030095bfab0303fd2e813dc3c37416b99603bf2c0003 }


condition:
	$a0
}