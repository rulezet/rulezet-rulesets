rule Win_Trojan_SillyC_203
{
strings:
	$a0 = { 014956741633c98bd1b80042cd21720b33d22e8b0e1601b440cd21b43ecd210e1fe94cffba }


condition:
	$a0
}