rule Win_Trojan_Nowi_1
{
strings:
	$a0 = { 450059ba0001b440cd21b801578b0e2d068b162f06cd21e82400e8130058e947ff5553412048 }


condition:
	$a0
}