rule Win_Trojan_WhiteNoize_1
{
strings:
	$a0 = { 0bcd2181fe4365747b8cc0488ed8812e03008000812e }


condition:
	$a0
}