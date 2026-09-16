rule Win_Trojan_G_16
{
strings:
	$a0 = { 9abe15b698b7af911ecd1677fed1162ca237db56186825be8fcf1635db56a237af7316cdf177db56 }


condition:
	$a0
}