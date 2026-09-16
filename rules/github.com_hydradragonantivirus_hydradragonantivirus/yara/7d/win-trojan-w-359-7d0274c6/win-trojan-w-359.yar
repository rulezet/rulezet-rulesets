rule Win_Trojan_W_359
{
strings:
	$a0 = { 51b90400000083f9040f8545feffffd9d0d9d0d9d059c3e8e2feffff3c010f841cffffff3c020f8454ffffff3c03 }


condition:
	$a0
}