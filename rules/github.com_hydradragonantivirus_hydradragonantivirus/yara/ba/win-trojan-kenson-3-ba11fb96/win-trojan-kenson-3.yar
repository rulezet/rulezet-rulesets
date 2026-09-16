rule Win_Trojan_Kenson_3
{
strings:
	$a0 = { d80500108ec0be00018bfeb18bf3a48ed81eb8180150cb33d2b41acd21ba5401b53fb44ecd21726eba1e00b8023dcd }


condition:
	$a0
}