rule Win_Trojan_Hupigon_746
{
strings:
	$a0 = { a8784c4416d49ea4743be3830097ce9a60cc30a2d1dabb7c0bc27b516102b7502110db8adb30df3badff7dda496d0d78076bb8e06253b5a5861f1daadfce2c866e79716d50aea0bef79d30a1fab5 }


condition:
	$a0
}