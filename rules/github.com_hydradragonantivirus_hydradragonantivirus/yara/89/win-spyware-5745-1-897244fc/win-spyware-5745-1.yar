rule Win_Spyware_5745_1
{
strings:
	$a0 = { a16cad4000bad8524000e8f1d6ffff75158b03bad0534000e8e3d6ffff7507c605f1ab400001 }


condition:
	$a0
}