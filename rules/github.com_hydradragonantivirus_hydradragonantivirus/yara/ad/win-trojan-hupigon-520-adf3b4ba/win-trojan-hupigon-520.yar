rule Win_Trojan_Hupigon_520
{
strings:
	$a0 = { eac6944e8e49eb7c2152e24e1c8e346983fd14dd53b9c8dfcc223df371d72a37c3dde55add23e50e526530c8701652ea936073a6453d8c865f7c0aab3985c5d8da9e6f526d6ed9bf7568f8fee3f3 }


condition:
	$a0
}