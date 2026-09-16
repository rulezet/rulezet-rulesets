rule Win_Trojan_HBV_1
{
strings:
	$a0 = { b440cd21e80700be0500e80dfbc3515350bb03002ea0cf07b9d2032e300743e2fa585b59c3 }


condition:
	$a0
}