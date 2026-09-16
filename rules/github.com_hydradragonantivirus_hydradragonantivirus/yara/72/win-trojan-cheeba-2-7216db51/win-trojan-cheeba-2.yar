rule Win_Trojan_Cheeba_2
{
strings:
	$a0 = { 0eb80001508cc805e00050b8700750cb }

	$a1 = { be0001fc2e8034??4681fe????75f5 }


condition:
	$a0 and $a1
}