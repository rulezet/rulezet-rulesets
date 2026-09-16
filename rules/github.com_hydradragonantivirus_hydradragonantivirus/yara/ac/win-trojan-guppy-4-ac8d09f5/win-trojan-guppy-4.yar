rule Win_Trojan_Guppy_4
{
strings:
	$a0 = { 33d233c9cd2197b440b19889f283ea40cd21 }


condition:
	$a0
}