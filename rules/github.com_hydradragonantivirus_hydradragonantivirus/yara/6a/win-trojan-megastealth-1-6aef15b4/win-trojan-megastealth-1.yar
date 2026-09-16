rule Win_Trojan_MegaStealth_1
{
strings:
	$a0 = { 0402cd12b106d3e08ec0b8020233db32f6b902000ad27805b90000b600cd13be4c00bf6402 }


condition:
	$a0
}