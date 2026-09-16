rule Win_Trojan_Body_1
{
strings:
	$a0 = { 5d83ed03b961038bfd2ef6551347e2f9afada9e1f9 }


condition:
	$a0
}