rule Win_Trojan_February12_1
{
strings:
	$a0 = { d7fde9f0feb8dde7cd213de7dd74381e8cc0488ed8b88f }


condition:
	$a0
}