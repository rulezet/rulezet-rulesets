rule Win_Trojan_VGEN_551
{
strings:
	$a0 = { 1701b8f225cd21ba6c01b409cd21ba2a00b80031cd21fb505351525756551e0681fa7341753b8cc88ed8baf801b409 }


condition:
	$a0
}