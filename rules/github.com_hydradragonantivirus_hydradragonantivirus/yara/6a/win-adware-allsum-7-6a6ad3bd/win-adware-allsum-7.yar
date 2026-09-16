rule Win_Adware_Allsum_7
{
strings:
	$a0 = { 5756e8baaa000083f8015959750c57575756e8d8ab000083c4104683fe037ce083cfffe86aedffff6810270000ff158c8002105f5ec3 }


condition:
	$a0
}