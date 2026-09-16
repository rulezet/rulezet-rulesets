rule Win_Trojan_Antiwin_1
{
strings:
	$a0 = { 40ba00000e1fb97802cd21585a402ea359022ec7065b027803482ea361022e89165f025a580578 }


condition:
	$a0
}