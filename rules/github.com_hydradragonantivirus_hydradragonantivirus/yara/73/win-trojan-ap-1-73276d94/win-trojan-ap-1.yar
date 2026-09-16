rule Win_Trojan_AP_1
{
strings:
	$a0 = { c08ed8be4c00ad50ad501e07cd124848a31304b106d3e08ec0c7064c0075008c064e00fcb9000233ffbe007cf3a406 }


condition:
	$a0
}