rule Win_Trojan_Dikshev_18
{
strings:
	$a0 = { 4d41ba2801b44ecd21721abf9e008bd7b82e5bae75fda5a4cd21720993b22d87d1b440cd21c3 }


condition:
	$a0
}