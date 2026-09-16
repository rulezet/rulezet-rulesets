rule Win_Trojan_V2Px_1
{
strings:
	$a0 = { 2b01b8e99e904bb9c104310d2bda33d12bd82bd9310590474b90434246f840e2e9 }


condition:
	$a0
}