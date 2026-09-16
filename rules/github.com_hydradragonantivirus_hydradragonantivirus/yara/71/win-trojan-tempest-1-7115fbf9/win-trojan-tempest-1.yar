rule Win_Trojan_Tempest_1
{
strings:
	$a0 = { 050050eb1fb4408b5e048b4e088b5606cd21720f508b5e04d1e3818f2402001058eb0450e828 }


condition:
	$a0
}