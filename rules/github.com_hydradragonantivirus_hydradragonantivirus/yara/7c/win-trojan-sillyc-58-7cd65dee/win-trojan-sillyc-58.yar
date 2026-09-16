rule Win_Trojan_SillyC_58
{
strings:
	$a0 = { ba00ffb41acd21b44eba7e01cd21724fe87200b43fba2bffb105cd218bfa8bf5f3a6750ab43ecd21b44fcd21eb }


condition:
	$a0
}