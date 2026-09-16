rule Win_Spyware_Banker_3073
{
strings:
	$a0 = { 1ede781e796a7b975c8605692072543a7998b1ccaec6a2acfca5fb07e25c891b12226506658df1d0058280ada7acbeb14858e1a2f5e458ebc4e50b22e778 }


condition:
	$a0
}