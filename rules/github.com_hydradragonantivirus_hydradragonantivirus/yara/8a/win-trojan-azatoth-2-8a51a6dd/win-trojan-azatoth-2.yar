rule Win_Trojan_Azatoth_2
{
strings:
	$a0 = { 8ed8be12008b042d45008904832e0300459033f6b24d86148ed8 }


condition:
	$a0
}