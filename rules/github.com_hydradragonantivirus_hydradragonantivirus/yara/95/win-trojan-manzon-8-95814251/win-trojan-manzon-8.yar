rule Win_Trojan_Manzon_8
{
strings:
	$a0 = { 6c5454cb68cbde54d566f4519df9516c4854fc939653559df9516c55549326d420600e725d }


condition:
	$a0
}