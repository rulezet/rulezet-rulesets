rule Win_Trojan_CivilWar_6
{
strings:
	$a0 = { 2d030089868901b440b992008d960001cd21b800422bc999cd21b440b904008d968801cd21b4 }


condition:
	$a0
}