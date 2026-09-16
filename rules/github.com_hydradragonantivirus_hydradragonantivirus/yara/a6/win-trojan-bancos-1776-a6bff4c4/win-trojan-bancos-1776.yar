rule Win_Trojan_Bancos_1776
{
strings:
	$a0 = { 93061c535d29d2ef36ea585d64ddffe2d8e0d4c36818bd2cb185623108d4c4cf84e12ccedbcd9e3d25fe2f44ad607eda40b8da5426f8f48f975b0072c2380b9b2b035281a2f2 }


condition:
	$a0
}