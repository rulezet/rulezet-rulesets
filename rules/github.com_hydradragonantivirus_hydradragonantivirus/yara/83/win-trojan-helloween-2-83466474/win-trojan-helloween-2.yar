rule Win_Trojan_Helloween_2
{
strings:
	$a0 = { 1325ba4a01cd21c39c80fa0273132e803e1e0000750bb4 }


condition:
	$a0
}