rule Win_Trojan_SdBot_2
{
strings:
	$a0 = { 77594936e4fcc9aa76bb064d0ad63ef28827d9020db844b8660043f0d10754863ed47d031dec14b5d2642d0ba81dc2dd05915aa8f2cfd647 }


condition:
	$a0
}