rule Win_Trojan_VLAD_11
{
strings:
	$a0 = { 8ec2e80000bf0002fc5e83ee09b9bc011f8c94a200f3a4be840089c88eda394402740ba5a587fefdafabb8a4 }


condition:
	$a0
}