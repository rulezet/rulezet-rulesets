rule Win_Trojan_Helloween_6
{
strings:
	$a0 = { e8cd213d5423743f803c00750583fcf072358cc0488ec026803e00005a }


condition:
	$a0
}