rule Win_Trojan_Moskau_1
{
strings:
	$a0 = { 0e00fbcf8bf581c659018cc8cd01b440b920038bd5cd218bf581c659018cc8cd018bfc8b7516ff }


condition:
	$a0
}