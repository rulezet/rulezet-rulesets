rule Win_Trojan_Fr_1
{
strings:
	$a0 = { 894c14894416a1b100b91000250f002bc8b440ba7b00cd607225b440b9f503ba0000cd60 }


condition:
	$a0
}