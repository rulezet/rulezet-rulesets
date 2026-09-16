rule Win_Trojan_Mybot_5914
{
strings:
	$a0 = { 0e513ecf9e3ca909a0653c732bae63a95be2fa3163761b873cd481ac9d61cb7a309e416051d94d819645bd20a3e82a73fa918101967d9f }


condition:
	$a0
}