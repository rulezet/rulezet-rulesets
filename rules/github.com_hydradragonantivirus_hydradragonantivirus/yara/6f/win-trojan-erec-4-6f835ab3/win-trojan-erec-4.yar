rule Win_Trojan_Erec_4
{
strings:
	$a0 = { 21ba0000b98e02b440cd213d8e02751bb90000ba0000b80042cd21ba8e02b91c00b440cd217204 }


condition:
	$a0
}