rule Win_Trojan_Mybot_4961
{
strings:
	$a0 = { 3b859aaa32f70c9f62064a65c12a9f8c3d35317e89fd4aede3163def3cf5ee36df67124e3cfd4bd9aa7c783dfbceda7111185e7b61b0a6626825ac206dc564ad692b29c43522488fcd8a7d320997 }


condition:
	$a0
}