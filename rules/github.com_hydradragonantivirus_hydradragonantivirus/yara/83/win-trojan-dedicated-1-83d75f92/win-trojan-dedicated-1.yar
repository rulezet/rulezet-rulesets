rule Win_Trojan_Dedicated_1
{
strings:
	$a0 = { 592bcc83c10451ba9202b103b44ecd }


condition:
	$a0
}