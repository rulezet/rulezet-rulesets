rule Win_Trojan_V_57
{
strings:
	$a0 = { 0400c7444e95cb958edec55408b413cd2f1e52cd2f58bff800ab58ab8edec544403bc7ab8cd8ab06577509d1e6b9ff00f3a77447b452cd2106bef80026c47f }


condition:
	$a0
}