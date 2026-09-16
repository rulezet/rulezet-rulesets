rule Win_Trojan_Patras_3
{
strings:
	$a0 = { 1304b8409f8ec0a1357da3007ca0377da2027cb8050233dbb90200ba8000cd139a3a0730 }


condition:
	$a0
}