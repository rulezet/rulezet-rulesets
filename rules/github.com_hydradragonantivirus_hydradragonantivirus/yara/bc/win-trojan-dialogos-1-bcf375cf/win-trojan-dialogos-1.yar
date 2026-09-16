rule Win_Trojan_Dialogos_1
{
strings:
	$a0 = { 9cbe0a00bf0000bb560403de8a0d880f474381ff000175f4bb4d0403de8a844a0488078a844b048847018a844c0488 }


condition:
	$a0
}