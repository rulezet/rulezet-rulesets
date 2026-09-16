rule Win_Trojan_Skinner_1
{
strings:
	$a0 = { 1e0e0e071fe800005d81ed0901b4098d96ca02cd218db6a4018dbe9c01b90400f3a5b8cefacd2181fbcefa7503e950 }


condition:
	$a0
}