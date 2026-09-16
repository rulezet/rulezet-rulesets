rule Win_Adware_Navipromo_1
{
strings:
	$a0 = { 5333d2c0eb0db8a6aa40006623db6623d36623ca2da6 }

	$a1 = { 3948520a6b1b4652 }

	$a2 = { 33796f30412d6d1bcbe928 }

	$a3 = { 4c7b2f3040 }


condition:
	$a0 and $a1 and $a2 and $a3
}