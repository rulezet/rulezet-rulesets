rule Win_Trojan_SillyC_227
{
strings:
	$a0 = { 40b902008d969a01cd21b80242b90000ba0000cd213e83869a01035bb440b9be008d960001cd21 }


condition:
	$a0
}