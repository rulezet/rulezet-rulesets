rule Win_Trojan_IRCBot_279
{
strings:
	$a0 = { 95ed555617e4c59ac8aca21d141f2e4383c00b50abf173f1c617ab9435caa4ffa1388086e32d03909a962c56f13e4a2329438fa96bd2a3418cfaffab7decce8aaaf6414e409d4dd4c3b47bf3b9f131f6 }


condition:
	$a0
}