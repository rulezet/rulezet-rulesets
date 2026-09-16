rule Win_Trojan_EVC_1
{
strings:
	$a0 = { db8ec326ff3684008f06470126ff3686008f064901b82125ba0301cd21fb07ba7d00cd27 }


condition:
	$a0
}