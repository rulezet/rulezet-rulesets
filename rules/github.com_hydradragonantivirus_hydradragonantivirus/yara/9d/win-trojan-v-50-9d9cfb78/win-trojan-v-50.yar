rule Win_Trojan_V_50
{
strings:
	$a0 = { 33ff8e5d02817d0433ff74298cc8488ed8b83f002945032945128e4512b9f300f32ea52bf78ed9b85f00b102 }


condition:
	$a0
}