rule Win_Trojan_DST_7
{
strings:
	$a0 = { 0301b90d02b440e89b00b8004233c933d2e89100583d00007409baf002b91800eb0f902ea10803 }


condition:
	$a0
}