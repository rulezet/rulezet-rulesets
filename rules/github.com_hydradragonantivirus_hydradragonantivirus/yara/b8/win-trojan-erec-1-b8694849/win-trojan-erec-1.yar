rule Win_Trojan_Erec_1
{
strings:
	$a0 = { 01b440cd213df101751bb90000ba0000b80042cd21baf101b91c00b440cd217204ff0e82001f }


condition:
	$a0
}