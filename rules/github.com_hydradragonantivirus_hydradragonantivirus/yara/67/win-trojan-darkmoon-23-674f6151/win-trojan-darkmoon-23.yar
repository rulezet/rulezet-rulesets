rule Win_Trojan_Darkmoon_23
{
strings:
	$a0 = { b8b8b24100ba7c844100e856bdfeff8d85d8feffffe84b1affff8b85d8feffffe870c0feff8bd08d85dcfeffffe80fbefeff8b95dcfeffffb864aa4100b994844100e89abefeff }


condition:
	$a0
}