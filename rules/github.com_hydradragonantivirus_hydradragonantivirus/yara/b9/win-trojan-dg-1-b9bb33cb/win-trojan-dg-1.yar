rule Win_Trojan_DG_1
{
strings:
	$a0 = { 5b0233c933d232c0cd21b4408b9c5b02b903008b94550283ea0389945802ba570203d6cd21b4 }


condition:
	$a0
}