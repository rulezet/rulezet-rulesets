rule Win_Spyware_4097_1
{
strings:
	$a0 = { 605781e7f45797792b34245f618bc7e8 }


condition:
	$a0
}