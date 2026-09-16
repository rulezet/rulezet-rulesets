rule Win_Spyware_Banker_2582
{
strings:
	$a0 = { edb44210c6f141682cbcaede05429a7d189ff87bf6e446849423a55340bd803a1d5d9bff27a7231cf166e1c778dd10cccffb84308a66cc924383c480b85faf3e32b1533c1820dc3edfb1359f8a774fa8 }


condition:
	$a0
}