rule Win_Trojan_Mybot_7230
{
strings:
	$a0 = { 02e0a300f42187daf24c68ad2da088ffe64a4d0d060f20f91a694d0b67fc4b6ef7aee6b47463090662f6a2259bfeb9e874c15fac76085b269e5a745debb81baacc005cb3e458e9d0cf84fee81fc6 }


condition:
	$a0
}