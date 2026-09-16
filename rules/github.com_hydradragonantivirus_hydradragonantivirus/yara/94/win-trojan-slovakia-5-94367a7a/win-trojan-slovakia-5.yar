rule Win_Trojan_Slovakia_5
{
strings:
	$a0 = { 1b8b163e0ffceb4590cd138b1ab40081e1f0048b1c7510b82010b99d01f2ae }


condition:
	$a0
}