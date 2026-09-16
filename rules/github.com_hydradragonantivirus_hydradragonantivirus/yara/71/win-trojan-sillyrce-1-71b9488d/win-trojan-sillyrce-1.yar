rule Win_Trojan_SillyRCE_1
{
strings:
	$a0 = { ee031e33c08ec0bf000257fcaf5f751856b90901902ef3a4be84005626a526a55fb84f02ab91ab5e0781c64b0058 }


condition:
	$a0
}