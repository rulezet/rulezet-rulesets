rule Win_Trojan_Bancos_1885
{
strings:
	$a0 = { 71bf48b07264cf4298d5b96e3e3616c74e521ab2fb10ec3b4c3cc6bacad9ce0bdeacbef33c2237b8291e2877f3ae6671f15bde89970be56bd72159c30512929fe7a5f91b16a6 }


condition:
	$a0
}