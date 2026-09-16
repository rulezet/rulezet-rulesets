rule Win_Trojan_Delta_3
{
strings:
	$a0 = { 70b000e6710e1fb409ba2a01cd21ba1c02b840008ed88b1e6c003b1e6c0074faa16c002bc3 }


condition:
	$a0
}