rule Baseking_RCE__8_byt_12_
{
strings:
	$a0 = { 0b162c58b071e2d5bb67ce8d }

condition:
	$a0
}