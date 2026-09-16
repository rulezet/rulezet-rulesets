rule Win_Trojan_Treb_2
{
strings:
	$a0 = { fa6677d9c4273f630664cf918cacb3ab4168e953e91fc744 }


condition:
	$a0
}