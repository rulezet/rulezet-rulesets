rule Win_Trojan_Vienna_128
{
strings:
	$a0 = { b9d105bf????8a45ff8bdf4b2807e2fb }


condition:
	$a0
}