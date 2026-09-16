rule Win_Trojan_Andromeda_7
{
strings:
	$a0 = { e90000e80000cc8bfc368b2d81ed06014444e81600eb2be81100b440b9d9008d960301cd21e80300c3 }


condition:
	$a0
}