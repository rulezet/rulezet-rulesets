rule Win_Trojan_Dan_II_1
{
strings:
	$a0 = { 5ee4403c9075fa2e30441e901e0e1fbb240003deb9540483e927908a0734c9880743e2f7 }


condition:
	$a0
}