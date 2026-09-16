rule Win_Trojan_CeCe_2
{
strings:
	$a0 = { f809744e535252c9600d2ae67e0252219a56a873ab321778d06b2a3fe217a290f6d37e8f78bd7eac }


condition:
	$a0
}