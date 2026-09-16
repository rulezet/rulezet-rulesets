rule Win_Spyware_6644_1
{
strings:
	$a0 = { 565e535383c40483c4048b5c24 }


condition:
	$a0
}