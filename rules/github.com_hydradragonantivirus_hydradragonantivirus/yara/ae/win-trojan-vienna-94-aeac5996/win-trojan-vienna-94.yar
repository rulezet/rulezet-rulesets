rule Win_Trojan_Vienna_94
{
strings:
	$a0 = { 0390ba271bbf261b8bef8a054d8a66002ae0886600e2f590 }


condition:
	$a0
}