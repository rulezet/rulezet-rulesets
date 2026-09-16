rule Win_Trojan_Foma_1
{
strings:
	$a0 = { 53515257061ee82fff0e1f897512c7451a0001c745089806c6858100008bf7fa0633c08ed8bb0400c43f26ff352e8f }


condition:
	$a0
}