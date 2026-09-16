rule Win_Trojan_B_10
{
strings:
	$a0 = { eb1c80fa80750488160b02fcb9a001be1e00bf1e02f3a4b80103419cff1e0700 }


condition:
	$a0
}