rule Win_Adware_Lop_176
{
strings:
	$a0 = { b8290d8cdbd45a3d50164905440dd8678370a2d6a84ee77ebf5d6392548de21106568a7142f6bed3fe9c04df8ec6dab4cfeede0c75ab430e5a66c5ac }


condition:
	$a0
}