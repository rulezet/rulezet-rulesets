rule Win_Trojan_Mephisto_9
{
strings:
	$a0 = { 2e8dbe1501b946022e8bb6a2052e31354747e2f961c3 }


condition:
	$a0
}