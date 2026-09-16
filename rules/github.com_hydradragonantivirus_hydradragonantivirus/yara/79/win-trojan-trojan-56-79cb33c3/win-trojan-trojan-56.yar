rule Win_Trojan_Trojan_56
{
strings:
	$a0 = { 3664424e46b8102f32a28baa6aaf968e157f8ec480e28ec591b6584ecfa8676342081b503abecab2afbdb3d9b9bc5375 }


condition:
	$a0
}