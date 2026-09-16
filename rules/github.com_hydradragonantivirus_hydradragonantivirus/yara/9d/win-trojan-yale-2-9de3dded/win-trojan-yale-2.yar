rule Win_Trojan_Yale_2
{
strings:
	$a0 = { c08ed0bc007cfbbb40008edba11300f7e32de0078ec00e1f81ff56347504ff0ef87d89e689f7b90002fcf3a489cebf807bb98000f3a4e81500060f1e0789 }


condition:
	$a0
}