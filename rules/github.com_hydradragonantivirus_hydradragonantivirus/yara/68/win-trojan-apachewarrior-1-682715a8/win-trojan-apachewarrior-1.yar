rule Win_Trojan_ApacheWarrior_1
{
strings:
	$a0 = { 03002bc18db61a028dbe5c01a5a4c644fde98944fe5133c9e8adffe8d6ffb4408d961a0259cd21 }


condition:
	$a0
}