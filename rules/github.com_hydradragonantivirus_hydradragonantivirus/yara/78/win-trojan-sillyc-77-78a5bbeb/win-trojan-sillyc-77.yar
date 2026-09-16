rule Win_Trojan_SillyC_77
{
strings:
	$a0 = { 8986bb0132c0e83f00b440b903008d96ba01cd21b002e82f00b440b9b8008d960301cd21b80157 }


condition:
	$a0
}