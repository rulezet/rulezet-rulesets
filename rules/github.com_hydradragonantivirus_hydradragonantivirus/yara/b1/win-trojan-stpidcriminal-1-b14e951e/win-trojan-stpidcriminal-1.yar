rule Win_Trojan_StpidCriminal_1
{
strings:
	$a0 = { 80c103463bf775f659c3b82435cd21 }


condition:
	$a0
}