rule Win_Trojan_Small_5333
{
strings:
	$a0 = { 69b96f7db997b2ea6498fe416ad830dbbcfc419f19adecb6fd0556b8fc0b4a140070414291fe3d0afb037734ad2f51bfa43733f3a773fb6dedb271802efae835e4399cbfa5acec41eba877c5d77e }


condition:
	$a0
}