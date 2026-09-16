rule Win_Adware_Casino_23
{
strings:
	$a0 = { 436865636b436173696e6f416c697665546872656164 }

	$a1 = { 436173696e6f496e506f6b6572 }


condition:
	$a0 and $a1
}