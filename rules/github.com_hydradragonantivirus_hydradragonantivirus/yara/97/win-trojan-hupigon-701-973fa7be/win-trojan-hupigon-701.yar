rule Win_Trojan_Hupigon_701
{
strings:
	$a0 = { da2d4a9ed1bdf49f0b981c4f1777a6498ae736c8d880c89654f649d2b496f62c98f29c2551ce39a333bf775f613834d276d8cc4ebd1a49865a7fabe8 }


condition:
	$a0
}