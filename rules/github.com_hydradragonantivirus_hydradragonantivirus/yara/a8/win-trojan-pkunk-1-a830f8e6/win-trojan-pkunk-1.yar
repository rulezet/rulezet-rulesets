rule Win_Trojan_Pkunk_1
{
strings:
	$a0 = { f801e8740061680001c38db61602e868008bd88db62202e85f0080be3e02e975108db61c02e8 }


condition:
	$a0
}