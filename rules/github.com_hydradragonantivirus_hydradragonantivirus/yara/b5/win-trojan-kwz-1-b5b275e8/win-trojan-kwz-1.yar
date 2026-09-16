rule Win_Trojan_KWZ_1
{
strings:
	$a0 = { 03002ea31503b440b90300ba14039c2eff1e0d03e85300b440b91d03ba00009c2eff1e0d03b457 }


condition:
	$a0
}