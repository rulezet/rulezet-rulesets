rule Win_Trojan_Onlinegames_17
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d }

	$a1 = { 2f6d616e6167652f66667869323030392f6765742e617370 }

	$a2 = { 706f6c2e657865 }


condition:
	$a0 and $a1 and $a2
}