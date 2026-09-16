rule Win_Trojan_Hymn_1
{
strings:
	$a0 = { b9490790b440e877fe722733c875238bd1b80042e869fe }


condition:
	$a0
}