rule Win_Trojan_USTC_1
{
strings:
	$a0 = { 8f8e84c040e2145008c164cb76e15b082501a956d0d60451f66c5ae1660361962ed226ef56b8fb09 }


condition:
	$a0
}