rule Win_Trojan_Onkelz_3
{
strings:
	$a0 = { 5d81ed08018db62801e80400eb123b008b9616018bfeb9ec01ac32c2aae2fac3 }


condition:
	$a0
}