rule Win_Trojan_FFI_1
{
strings:
	$a0 = { 964002cd21b44b8d969b01b9270080f405cd21b8824a3580778d965e02cd2193b430b90300 }


condition:
	$a0
}