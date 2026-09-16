rule Win_Trojan_Wvp_1
{
strings:
	$a0 = { 3e7e0257567435b8024233d28bcacd213d7f017223050001a37301b440b97e01ba7e02cd21 }


condition:
	$a0
}