rule Win_Trojan_Erase26_3
{
strings:
	$a0 = { 03008ed8b002b91400ba0000bb0000cd267203eb0b90ba0040b409cd21eb0890ba0b40b409cd21b44ccd2100000000 }


condition:
	$a0
}