rule Win_Trojan_Mateo_1
{
strings:
	$a0 = { b92203ba380103d58bda03d9eb01122e8a0751eb01ea8aae9404eb011232c559eb01ea2e8807eb0112e2dd }


condition:
	$a0
}