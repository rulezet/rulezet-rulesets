rule Win_Trojan_WereWolf_8
{
strings:
	$a0 = { 2eb8350e9b474781ffa30272f3c32ec606a80281eb }


condition:
	$a0
}