rule Win_Trojan_Sirius_38
{
strings:
	$a0 = { 1e5e507ca3a3e95d507a9676ef7ba2bc252f35b2375a9653afcc8e59ef7b9a5822e3285ad8c3ef7c }


condition:
	$a0
}