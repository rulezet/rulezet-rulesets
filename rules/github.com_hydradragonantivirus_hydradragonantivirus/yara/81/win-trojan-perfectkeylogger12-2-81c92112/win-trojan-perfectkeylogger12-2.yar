rule Win_Trojan_PerfectKeylogger12_2
{
strings:
	$a0 = { 42b719d858f2e4f919c21bd4ffff144d6c617a696e6720546f6f6c735c50657266f7031b976b203d6c6f67671bb73fedf05c312e320e5f4d6963726f731a5c49 }


condition:
	$a0
}