rule Win_Trojan_Vienna_38
{
strings:
	$a0 = { 2c008b768f8b7e8bac3c3b74093c007403aaebf433f6 }


condition:
	$a0
}