rule Win_Trojan_VGEN_695
{
strings:
	$a0 = { 0301eb019081fc00407705b8014ccd21eb0690b8004ccd2156b419cd21a20701b4472ad2be1001cd215e56c60400 }


condition:
	$a0
}