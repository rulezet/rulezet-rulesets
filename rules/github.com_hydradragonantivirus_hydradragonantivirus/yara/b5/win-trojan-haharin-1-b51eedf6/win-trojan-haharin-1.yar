rule Win_Trojan_Haharin_1
{
strings:
	$a0 = { cd1326817f3eb801740c26803f6a7406b8010341cd130e1ffe06027c7542b408cd138ac1243f }


condition:
	$a0
}