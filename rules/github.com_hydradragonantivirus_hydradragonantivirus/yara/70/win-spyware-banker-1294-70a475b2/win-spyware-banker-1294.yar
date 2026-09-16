rule Win_Spyware_Banker_1294
{
strings:
	$a0 = { b5e9e6e80d6cdb2ecb9891bf0c0f2c81ad92b0e3380c2109f1fd543887b025b511885884abce3ad76bc685f6ed2ca1a029ba98f69e755cf6c1d50e645ac7710e590f1c16 }


condition:
	$a0
}