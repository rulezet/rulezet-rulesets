rule Win_Spyware_Banker_2117
{
strings:
	$a0 = { 6b738c4c6515eb7e559f115f609ef8fa5060665d723fb36fb399dbfda563ffb8f56ba03681cf851332a98b338823d69cb3540af10af7b17ba86d927e9cdcf8cd5ec72d154e32657ffc4ea3fc4d44 }


condition:
	$a0
}