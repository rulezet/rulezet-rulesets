rule Win_Adware_Openshopper_3
{
strings:
	$a0 = { 188016687474703a2f2f7368617265626f782e636f2e6b7220300d06092a8648 }


condition:
	$a0
}