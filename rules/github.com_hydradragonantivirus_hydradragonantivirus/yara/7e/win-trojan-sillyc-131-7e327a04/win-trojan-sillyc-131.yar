rule Win_Trojan_SillyC_131
{
strings:
	$a0 = { 40b90300ba80facd21b8024233c933d2cd21b440ba87fab90300cd21b4405a52b9ea00cd21b440 }


condition:
	$a0
}