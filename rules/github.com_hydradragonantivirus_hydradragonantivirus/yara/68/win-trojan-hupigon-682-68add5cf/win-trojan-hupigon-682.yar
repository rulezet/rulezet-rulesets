rule Win_Trojan_Hupigon_682
{
strings:
	$a0 = { 604650ffac7c0194c346be3da3a2862e7a4e23715eda040d2d9667e29ee7d0e91c6c3742102da7d766a6b108ff9ed900ff0f3788ccc7789c78bf220b }


condition:
	$a0
}