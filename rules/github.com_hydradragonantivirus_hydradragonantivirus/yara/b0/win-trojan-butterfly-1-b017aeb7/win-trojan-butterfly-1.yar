rule Win_Trojan_Butterfly_1
{
strings:
	$a0 = { 01e800005d81ed0b01bf00018db60501b90400fcf3a4b41a8d96??02cd21c686??0200b44e8db6??028d96??0252eb??b41aba8000cd21[0-12]bcfeffbd00015533edc30bdb7419b5008a8e??02b801578b8e??028b96??02cd21b43ecd2133db }


condition:
	$a0
}