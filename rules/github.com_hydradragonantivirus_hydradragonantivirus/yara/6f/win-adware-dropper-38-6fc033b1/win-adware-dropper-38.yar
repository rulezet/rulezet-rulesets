rule Win_Adware_Dropper_38
{
strings:
	$a0 = { 2e657169736f2e636f6d2f736f66612e68746d6c300d06092a86 }


condition:
	$a0
}