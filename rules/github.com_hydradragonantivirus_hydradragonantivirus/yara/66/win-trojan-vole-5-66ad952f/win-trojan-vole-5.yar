rule Win_Trojan_Vole_5
{
strings:
	$a0 = { b440b9f7018d960600cd21e80500b43ecd21c38db63300b9a501803400464975f9c3 }


condition:
	$a0
}