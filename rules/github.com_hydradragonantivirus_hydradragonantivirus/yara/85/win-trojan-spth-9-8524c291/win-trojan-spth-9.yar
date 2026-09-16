rule Win_Trojan_Spth_9
{
strings:
	$a0 = { 72756e5d20403d22737461727420636f6d6d616e64202f63206563686f2064756d6d }

	$a1 = { 403d2264756d6d }


condition:
	$a0 and $a1
}