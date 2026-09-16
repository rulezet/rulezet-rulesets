rule Win_Trojan_Mahon_2
{
strings:
	$a0 = { c686470501b440b916058d960501cd21e8ac01b440b91c008d964c05cd21e89001b43ecd21 }


condition:
	$a0
}