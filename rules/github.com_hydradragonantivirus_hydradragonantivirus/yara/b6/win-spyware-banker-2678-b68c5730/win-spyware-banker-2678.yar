rule Win_Spyware_Banker_2678
{
strings:
	$a0 = { 0c647196fb1cb738ce9a47a30ba51a444e13498572eca92725901c0b925eb27f980546a17d47ab1adba2bec8367a8e0b0b67b0a83a2ada4e454d8a655b3ff39bea17ddcfeb719f473106fca8da93 }


condition:
	$a0
}