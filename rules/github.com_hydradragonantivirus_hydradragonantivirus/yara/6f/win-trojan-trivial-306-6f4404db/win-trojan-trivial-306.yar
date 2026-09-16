rule Win_Trojan_Trivial_306
{
strings:
	$a0 = { b44eba1d0149cd21ba9e00b8013dcd218bd8ba0001b93500b440cd21c3 }


condition:
	$a0
}