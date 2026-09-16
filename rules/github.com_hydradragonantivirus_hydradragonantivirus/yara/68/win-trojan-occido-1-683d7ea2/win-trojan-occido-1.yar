rule Win_Trojan_Occido_1
{
strings:
	$a0 = { 960102b90300cd21b802429933c9cd218db60301b931018dbe3402f3a48db65602b205b9df }


condition:
	$a0
}