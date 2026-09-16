rule Win_Trojan__0117_0001_000_1
{
strings:
	$a0 = { 3d078db60801e868008d963d07b440cd218f86ff01b80042e82b008d96fa01b90500b440cd }


condition:
	$a0
}