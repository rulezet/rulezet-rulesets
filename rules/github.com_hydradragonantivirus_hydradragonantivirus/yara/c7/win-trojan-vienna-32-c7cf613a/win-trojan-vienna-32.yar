rule Win_Trojan_Vienna_32
{
strings:
	$a0 = { b440b90500ba1302cd21810e42021f00 }


condition:
	$a0
}