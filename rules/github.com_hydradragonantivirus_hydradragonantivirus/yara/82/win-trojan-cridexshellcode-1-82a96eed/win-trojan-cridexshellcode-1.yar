rule Win_Trojan_CridexShellCode_1
{
strings:
	$a0 = { eb0600000000eb05e8f9ffffff5a83c21887d68bfe33c966b9e001fcad35959fab87abe2f7050f4387 }

	$a1 = { 959f200c459fab871edea3841643ab8795162873959fab397d9cab877de3ab8795d1de7f }


condition:
	$a0 and $a1
}