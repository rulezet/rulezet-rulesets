rule Win_Adware_Digitalnames_2
{
strings:
	$a0 = { 6674703a2f2f000048545450533a2f2f }

	$a1 = { 6f7265725c56657273 }

	$a2 = { 6469676974616c6e616d6573 }


condition:
	$a0 and $a1 and $a2
}