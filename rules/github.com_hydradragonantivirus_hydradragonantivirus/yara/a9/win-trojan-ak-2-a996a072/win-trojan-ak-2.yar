rule Win_Trojan_AK_2
{
strings:
	$a0 = { 77b13e8986fe012d03002e8986f300b8004233c933d2cd21b440b905008bd581c2f200cd21 }


condition:
	$a0
}