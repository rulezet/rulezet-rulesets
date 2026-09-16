rule Win_Trojan_Messa_1
{
strings:
	$a0 = { 92ffb6bab2b59fd192f899829e9fd492f89f979ccf9c63fb9fc592f89f979c9fc492f89f979c9f9c63fb92f89f979c9ef899829ee29fe1e0 }


condition:
	$a0
}