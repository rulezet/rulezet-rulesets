rule Win_Trojan_Small_3950
{
strings:
	$a0 = { 83caff425252beb8??4000ff1609c0752e89c281c2cb??41f081c23565ff0f8d8a3cf5ffff81c1001000005205f0dfafb12902832a0f31c08d520439ca7eedbed6??4000ff16c3 }


condition:
	$a0
}