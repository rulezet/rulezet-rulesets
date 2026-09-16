rule Win_Trojan_Gen_253
{
strings:
	$a0 = { 89165002b430cd218b2e02008b1e2c008edaa3dd1d8c06db1d891ed71d892eef1dc706e11dffff8ec333c0b9ff }


condition:
	$a0
}