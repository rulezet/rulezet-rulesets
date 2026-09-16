rule Win_Trojan_Spooky_10
{
strings:
	$a0 = { ed0601b8cefacd2181fbcefa7503e953002e812e020080008cc8488ed8812e0300800033c08ed8832e130402a113 }


condition:
	$a0
}