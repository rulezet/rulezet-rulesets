rule Win_Trojan_Soulfly_1
{
strings:
	$a0 = { 23f97401eab866dbbbfb83cd213d1211750981fbe71e7503e9b500b80258cd2172219850b8 }


condition:
	$a0
}