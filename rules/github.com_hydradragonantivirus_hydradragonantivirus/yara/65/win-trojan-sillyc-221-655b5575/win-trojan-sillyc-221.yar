rule Win_Trojan_SillyC_221
{
strings:
	$a0 = { 98ffe889ffe80cfe8bc883f112e33556591e5ab800708e }


condition:
	$a0
}