rule Win_Trojan_Hupigon_679
{
strings:
	$a0 = { 6ca79070641498223129d0cc739f43984f8d2d7d8720da94c8bf3b5d3541435576e608b2effc07d64a70f54dbc9614d2a748d4ce6b31d5de4ece01667c6d1b5f42 }


condition:
	$a0
}