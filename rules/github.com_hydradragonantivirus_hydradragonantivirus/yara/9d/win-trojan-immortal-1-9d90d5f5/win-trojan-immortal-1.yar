rule Win_Trojan_Immortal_1
{
strings:
	$a0 = { 0800501e0e1f0e07b430cd213c037215b80012cd2f3cff750cb8001dbb574dcd210ac074211f8cd88ec02e01849a06 }


condition:
	$a0
}