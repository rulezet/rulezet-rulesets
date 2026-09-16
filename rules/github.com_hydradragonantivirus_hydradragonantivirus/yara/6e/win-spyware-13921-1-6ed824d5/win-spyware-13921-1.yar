rule Win_Spyware_13921_1
{
strings:
	$a0 = { 506a00e836b6ffff8b1578914000c6040200e893f7ffff8d45bc8b1578914000b905010000e8d4abffff }


condition:
	$a0
}