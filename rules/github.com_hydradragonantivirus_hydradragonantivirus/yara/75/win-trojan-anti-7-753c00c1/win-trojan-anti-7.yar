rule Win_Trojan_Anti_7
{
strings:
	$a0 = { 967402cd2193b440b91f028d968002cd21b43ecd21b84143bb4f52cd213d555381fb215874588c }


condition:
	$a0
}