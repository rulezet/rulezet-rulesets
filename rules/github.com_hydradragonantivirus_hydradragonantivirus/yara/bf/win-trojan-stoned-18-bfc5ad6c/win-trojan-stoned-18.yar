rule Win_Trojan_Stoned_18
{
strings:
	$a0 = { c08ed88ed0bc007cfba113042d0400a31304ba4000f7e22ec7067a0181002ea37c018ec0be00 }


condition:
	$a0
}