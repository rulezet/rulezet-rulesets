rule Win_Spyware_Goldun_95
{
strings:
	$a0 = { 6361666565136f779b05e207d861641373312e6bd641d8bf11c46b792d6c6162731d1ef606c832 }


condition:
	$a0
}