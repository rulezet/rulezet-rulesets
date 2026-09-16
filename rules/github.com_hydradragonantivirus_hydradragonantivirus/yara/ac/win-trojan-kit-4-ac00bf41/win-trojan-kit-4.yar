rule Win_Trojan_Kit_4
{
strings:
	$a0 = { c5161900b82425cd21071f5f5e5a595b589de2ff2e1100 }


condition:
	$a0
}