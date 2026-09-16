rule Win_Trojan_Oxan_1
{
strings:
	$a0 = { 21b90000ba0000b80042cd2158050c012d0300a3e300c606e200e9bae200b90300b440cd21eb01 }


condition:
	$a0
}