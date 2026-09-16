rule Win_Trojan_IRCBot_372
{
strings:
	$a0 = { 6f72651e696e666563726f78 }

	$a1 = { 3486696c6c1fde760caca0a06a7310661a6d444e1c3c18141c65013f8c740dc30213ec5084672e9f7ae6ffffc100 }


condition:
	$a0 and $a1
}