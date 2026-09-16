rule Win_Trojan_FWord_1
{
strings:
	$a0 = { 0101b442b90000ba0000b000cd21b440b90500ba0001cd21b442b90000ba0100b002cd21 }


condition:
	$a0
}