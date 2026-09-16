rule Win_Trojan_VLAD_6
{
strings:
	$a0 = { 5d81ed03001e060e1f3ec7861300cd203ec78613003ec7b80163cd213bc374418cc0488ed8803e00005a753583 }


condition:
	$a0
}