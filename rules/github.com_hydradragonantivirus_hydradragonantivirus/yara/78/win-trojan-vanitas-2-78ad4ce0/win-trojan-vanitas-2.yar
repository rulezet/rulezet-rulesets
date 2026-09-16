rule Win_Trojan_Vanitas_2
{
strings:
	$a0 = { bbcefacd213dcefa7503e91601e83404b88716cd2f }


condition:
	$a0
}