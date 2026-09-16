rule Win_Trojan_Autorun_186
{
strings:
	$a0 = { 5b4175746f52756e5d0d0a3b34396155345a356f416f306c37736b6b71344164 }


condition:
	$a0
}