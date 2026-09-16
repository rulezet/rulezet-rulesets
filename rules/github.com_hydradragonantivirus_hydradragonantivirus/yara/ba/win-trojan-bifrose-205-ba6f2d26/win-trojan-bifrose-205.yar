rule Win_Trojan_Bifrose_205
{
strings:
	$a0 = { 968c790c2774de0c503ef5c595c5f26fc852d90ea7e3e9a47ade10c816cf8a1616f2db5030d441249a3b1de21cb7f395b6f0858e077cc1b37f36370264ce709fb4ae5b2eaffc5684721cd7e71d4d }


condition:
	$a0
}