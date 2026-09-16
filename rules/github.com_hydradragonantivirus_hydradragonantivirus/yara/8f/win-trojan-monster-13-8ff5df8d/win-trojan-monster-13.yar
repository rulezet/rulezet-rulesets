rule Win_Trojan_Monster_13
{
strings:
	$a0 = { 4bf26e6ff08f4b499c876b1cfe0d7898cb8ca14b876b14a103b4ceac4bfe50f06148499c876bcaf6 }


condition:
	$a0
}