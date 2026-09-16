rule Win_Trojan_Cls_1
{
strings:
	$a0 = { 8ed9b9d00729f63ec70400004646e2f75e1f592eff }


condition:
	$a0
}