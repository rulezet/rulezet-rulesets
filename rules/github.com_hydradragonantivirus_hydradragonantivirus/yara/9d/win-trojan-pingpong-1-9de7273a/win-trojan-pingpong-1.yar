rule Win_Trojan_PingPong_1
{
strings:
	$a0 = { f6b90100bf0300b001b4029c2eff1e387c730c30e4cd134f83ff0075eceb78061f803e3e }


condition:
	$a0
}