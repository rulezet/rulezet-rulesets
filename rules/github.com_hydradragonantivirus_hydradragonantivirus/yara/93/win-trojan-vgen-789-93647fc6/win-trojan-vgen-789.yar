rule Win_Trojan_VGEN_789
{
strings:
	$a0 = { ed03b96400be8000bf6aeffcf3a4be450103f5bf34efb90300fcf3a4b44eb92000ba340103d5cd217303e9cf0081 }


condition:
	$a0
}