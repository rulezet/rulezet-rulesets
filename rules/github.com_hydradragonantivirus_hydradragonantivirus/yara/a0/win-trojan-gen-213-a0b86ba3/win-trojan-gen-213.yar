rule Win_Trojan_Gen_213
{
strings:
	$a0 = { 5d005589e5b802029adf045d0081ec0202c606fe01009abd0c5d008946feb801003b46fe7f4da3fe02eb04ff06 }


condition:
	$a0
}