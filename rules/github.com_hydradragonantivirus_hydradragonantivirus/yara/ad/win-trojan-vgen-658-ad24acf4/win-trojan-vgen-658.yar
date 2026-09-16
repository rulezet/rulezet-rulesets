rule Win_Trojan_VGEN_658
{
strings:
	$a0 = { 33d28ec2e80000bf0002fc5e81ee0900b9ba011f8c94a300f3a4be84008bc18eda394402740ba5a587f7fdafabb8 }


condition:
	$a0
}