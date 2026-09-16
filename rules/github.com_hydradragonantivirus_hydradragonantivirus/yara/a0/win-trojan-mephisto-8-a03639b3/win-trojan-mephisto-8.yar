rule Win_Trojan_Mephisto_8
{
strings:
	$a0 = { be1501b91e022e8bb651052e31354747e2f9c3 }


condition:
	$a0
}