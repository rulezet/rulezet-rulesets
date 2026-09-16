rule Win_Trojan_Guppy_1
{
strings:
	$a0 = { c9b802422bd2cd21978bd6b19883ea40b440cd212bd2b800422bc9cd21b1032bf9 }


condition:
	$a0
}