rule Win_Trojan_8Tunes_1
{
strings:
	$a0 = { f6b9da03f3a550bb230353cb8ed0bc }


condition:
	$a0
}