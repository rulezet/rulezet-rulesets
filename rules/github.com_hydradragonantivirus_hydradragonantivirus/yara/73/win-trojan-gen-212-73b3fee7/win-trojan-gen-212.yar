rule Win_Trojan_Gen_212
{
strings:
	$a0 = { 01fcf2aef6d18a1f3ec14f8bf74efda8aa1f33c0a3fcff06c3bf0605bea100b9130090fc2e }


condition:
	$a0
}