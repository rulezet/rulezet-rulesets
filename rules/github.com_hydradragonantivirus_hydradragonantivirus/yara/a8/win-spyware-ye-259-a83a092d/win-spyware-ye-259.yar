rule Win_Spyware_ye_259
{
strings:
	$a0 = { 558bec81c46cffffff2bc313c12bfa13f3bb25b8ce9ef7d02bc1f7def7d68bc3 }


condition:
	$a0
}