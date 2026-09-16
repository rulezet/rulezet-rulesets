rule Win_Trojan_Spawnie_1
{
strings:
	$a0 = { 1e0e8cc801063801bada0003c28bd80591008edb8ec033f633ffb90800f3a54b484a79ee8ec3 }


condition:
	$a0
}