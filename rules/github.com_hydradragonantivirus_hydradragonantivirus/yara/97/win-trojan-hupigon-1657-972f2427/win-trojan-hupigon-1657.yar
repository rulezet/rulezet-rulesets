rule Win_Trojan_Hupigon_1657
{
strings:
	$a0 = { 4d4af35dbee16c50352942d077479d789b76e90c25aeb0b53568d4ed4aa6da63ed4ddb155eca89fc805f038b765db7ac48de576b7333540ed2425b918611ae84a7 }


condition:
	$a0
}