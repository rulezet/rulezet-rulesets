rule Win_Adware_Digitalnames_1
{
strings:
	$a0 = { 72006300680000007b003300300044 }

	$a1 = { 6f7265725c4d61696e }

	$a2 = { 4469676974616c4e616d6573 }


condition:
	$a0 and $a1 and $a2
}