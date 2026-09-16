rule Win_Trojan_VPK_1
{
strings:
	$a0 = { 01571e068b360101561ebb40008edb8b1e1a008b5ffe1f81c67a06895cfe8b44eab91600e8d5045e5681c63801b9 }


condition:
	$a0
}