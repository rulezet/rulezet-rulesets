rule Win_Trojan_Ice_2
{
strings:
	$a0 = { 49c6450463c645056589fab90600b440cd215a31c9b80042cd2131d2b9de02b440cd215a59 }


condition:
	$a0
}