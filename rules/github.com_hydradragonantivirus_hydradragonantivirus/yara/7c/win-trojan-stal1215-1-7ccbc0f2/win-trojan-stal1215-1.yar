rule Win_Trojan_STAL1215_1
{
strings:
	$a0 = { 836c3c08b440babf02b93e00cd21b8004233c9ba0004cd21b43fbabf02b90002cd218b441c }


condition:
	$a0
}