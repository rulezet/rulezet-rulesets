rule Win_Trojan_Vienna_52
{
strings:
	$a0 = { 03e9a3008bd8b80057cd21898c040089 }


condition:
	$a0
}