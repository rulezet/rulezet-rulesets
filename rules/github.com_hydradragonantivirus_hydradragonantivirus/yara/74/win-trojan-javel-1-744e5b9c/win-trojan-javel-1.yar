rule Win_Trojan_Javel_1
{
strings:
	$a0 = { 4b52454154495649545920464f52204b415453 }


condition:
	$a0
}