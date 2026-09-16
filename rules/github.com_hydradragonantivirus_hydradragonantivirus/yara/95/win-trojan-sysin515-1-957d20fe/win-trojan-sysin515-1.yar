rule Win_Trojan_SYSIN515_1
{
strings:
	$a0 = { 961602cd21b8024233c999cd21b440b912008d961802cd21b440b9f1018d961200cd21b801575a }


condition:
	$a0
}