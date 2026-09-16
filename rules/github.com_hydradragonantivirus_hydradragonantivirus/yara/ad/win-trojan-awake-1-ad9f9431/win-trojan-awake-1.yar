rule Win_Trojan_Awake_1
{
strings:
	$a0 = { 01be820103f3baaf0503d381345080463bf275f7e9 }


condition:
	$a0
}