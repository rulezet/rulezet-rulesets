rule Win_Trojan_BeastVir_1
{
strings:
	$a0 = { 83ed15fc8bf5bf0001b90300f3a4e859023981c47982c778c3c72fd6c67981c778c2c72fcfc62f60c77fc7c63827c5 }


condition:
	$a0
}