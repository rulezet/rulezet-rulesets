rule Win_Spyware_6785_1
{
strings:
	$a0 = { 55508bc483c004c70000c0171358c390 }


condition:
	$a0
}