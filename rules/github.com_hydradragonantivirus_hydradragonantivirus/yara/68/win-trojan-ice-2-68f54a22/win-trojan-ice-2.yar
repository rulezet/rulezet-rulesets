rule Win_Trojan_ICE_2
{
strings:
	$a0 = { 9ceb02b9b901ba1a0103d6cd21b801578b9ceb02b9 }


condition:
	$a0
}