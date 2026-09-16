rule Win_Trojan_Dikshev_4
{
strings:
	$a0 = { 682a3f5646ad5efec450404040955f87f7a5a48bd4b44ecd2172d1b891d9bae2fbf7eacd21 }


condition:
	$a0
}