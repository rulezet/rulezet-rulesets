rule Win_Trojan_ASP_25
{
strings:
	$a0 = { 636f707966696c65207366696c652c6d6266696c6570617468 }

	$a1 = { 6262732f746573742e617370 }


condition:
	$a0 and $a1
}