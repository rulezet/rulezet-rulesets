rule Win_Spyware_Banker_2577
{
strings:
	$a0 = { 9b9978b3dc67c5244a5b6c8ed6683851dda8f5293bf2f67445cab0e28e5d447211237535cd9dffadca9a3c70a2f82757424883425a0eccc5374ff1dd95cfecdc56e3ed84e9917cb3d0c7756b7cff578a }


condition:
	$a0
}