rule Win_Trojan_Defo_1
{
strings:
	$a0 = { 16fd7dbb7800ba427c36c5372e89363e7c2e8c1e407c8bfab90b00fcf3a48ed989178947028bfa }


condition:
	$a0
}