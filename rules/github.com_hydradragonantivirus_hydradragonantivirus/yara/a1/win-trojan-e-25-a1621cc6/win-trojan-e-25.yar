rule Win_Trojan_E_25
{
strings:
	$a0 = { cd2133ff8edfb7024fb8024acd2fb8104abb0100cd2fb30647742be8d1fff32ea4b85c028747fe50ff378c0f87cf }


condition:
	$a0
}