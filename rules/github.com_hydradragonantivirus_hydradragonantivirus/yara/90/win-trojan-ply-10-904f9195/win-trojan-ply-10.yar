rule Win_Trojan_Ply_10
{
strings:
	$a0 = { e2dde86c12b8e020052020e9651003d590cd219033c0908ed890bebc00bf690703fd90b90400e8 }


condition:
	$a0
}