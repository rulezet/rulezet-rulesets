rule Win_Trojan_Flashback_15
{
strings:
	$a0 = { 47455400557365722d4167656e740077620073797363746c }


condition:
	$a0
}