rule Win_Trojan_BadBrain_1
{
strings:
	$a0 = { b96203be38018bfefcad33060301ab49e302ebf559c3ba00018b1ee701b92a02 }


condition:
	$a0
}