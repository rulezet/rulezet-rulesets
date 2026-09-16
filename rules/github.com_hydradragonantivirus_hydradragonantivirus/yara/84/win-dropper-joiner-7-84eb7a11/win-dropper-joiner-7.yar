rule Win_Dropper_Joiner_7
{
strings:
	$a0 = { 33c9baa48f41008bc3e839f4ffff8d45f4e815f8ffff8d45f4bae08f4100e86cb6feff8b4df4bafc8f41008bc3e8d1f5ffff }


condition:
	$a0
}