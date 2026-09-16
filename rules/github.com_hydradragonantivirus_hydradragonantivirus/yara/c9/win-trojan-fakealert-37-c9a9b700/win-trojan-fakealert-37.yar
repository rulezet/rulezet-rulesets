rule Win_Trojan_Fakealert_37
{
strings:
	$a0 = { e812f0ffff6a1d5883f8027e083def0000007d014083c02c3d900000007ce98b0d40b0001085c97d06ff0d44b00010 }


condition:
	$a0
}