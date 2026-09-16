rule Win_Trojan_Doomsday_2
{
strings:
	$a0 = { 01b9ce02bebd048bd92800e2fa }


condition:
	$a0
}