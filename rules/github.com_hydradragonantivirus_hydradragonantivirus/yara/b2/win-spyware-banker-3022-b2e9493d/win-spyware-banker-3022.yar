rule Win_Spyware_Banker_3022
{
strings:
	$a0 = { 4916971f6cf614e3462c2c4e4dfd1c2b41573bada41aeec5f01fb07e88aba754cf48a3df7e3931bc4a417c8cb103de9f5130643eda8a67f11ecd1840372d37990e51fef0 }


condition:
	$a0
}