rule Win_Trojan_SillyE_10
{
strings:
	$a0 = { be2c008b040e0e1f07e80400909090905d9081ed0e0150b419cd213e88868e03b44732d28db69003cd213ec6868f }


condition:
	$a0
}