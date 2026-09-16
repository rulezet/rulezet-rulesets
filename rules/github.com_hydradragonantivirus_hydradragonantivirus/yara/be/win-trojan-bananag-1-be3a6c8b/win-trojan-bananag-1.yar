rule Win_Trojan_BananaG_1
{
strings:
	$a0 = { ba8501b44ecd217245b80043ba9e00cd2151b80143 }


condition:
	$a0
}