rule Win_Trojan_K4_2
{
strings:
	$a0 = { 84d602899cda02b803258bd681c22102cd21837c4600742a8bde83c34f8bfe81c7e0028b4c46d4 }


condition:
	$a0
}