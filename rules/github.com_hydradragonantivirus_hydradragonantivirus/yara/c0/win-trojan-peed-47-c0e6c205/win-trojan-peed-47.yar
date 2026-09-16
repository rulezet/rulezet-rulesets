rule Win_Trojan_Peed_47
{
strings:
	$a0 = { 29c98b6c241c83ed2d83ed3283ed644809ed75f8bf28f2cf0201c101f95189 }


condition:
	$a0
}