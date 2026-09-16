rule Win_Trojan_Camel_3
{
strings:
	$a0 = { 86a702a601b8024233c999cd21b440b9a6018d960301cd21b800573e8b96d7023e8b8ed50205 }


condition:
	$a0
}