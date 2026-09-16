rule Win_Trojan_Hupigon_541
{
strings:
	$a0 = { 07351e5f84574c9e880343f3aed636b9f607643b7751865e5d59f279e348c936535c9aaca3b7aa611c621b37bf79f00bedc2f59b742b4b8ae8e5f16acb366a889eeb71e48ee3b0465a1fdc6ca5cb }


condition:
	$a0
}