rule Win_Trojan_Trojan_914
{
strings:
	$a0 = { 247375626a656374203d20226d6f72666575732063616c6c732122 }


condition:
	$a0
}