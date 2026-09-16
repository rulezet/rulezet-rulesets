rule Win_Trojan_Nina_5
{
strings:
	$a0 = { 50b85397cd218cd8488ed8a103005306 }


condition:
	$a0
}