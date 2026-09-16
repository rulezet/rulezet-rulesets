rule Win_Trojan_SillyRC_22
{
strings:
	$a0 = { b91201ba000181c2e000cd217219b8004233c933d2cd21720eb440b90300ba0b0281c2e000cd }


condition:
	$a0
}