rule Win_Trojan_VGEN_780
{
strings:
	$a0 = { 2d049a0000cb035589e5e865c7c706f20100b8e8d1c49ac201cb03e851fe89ec5d31c09ad8002d04005e5a595b }


condition:
	$a0
}