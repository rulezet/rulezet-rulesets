rule Win_Trojan_Keylogger_45
{
strings:
	$a0 = { 1faa900072696e73742e6461 }

	$a1 = { 386e2556336a1193598d7dacf3f6beec8babd5f08d8d5b13ac502b5001df3cc77b5150c71b445e5d2cf7d81bc05f382c4e7009 }


condition:
	$a0 and $a1
}