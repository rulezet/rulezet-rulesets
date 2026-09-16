rule Win_Spyware_4752_2
{
strings:
	$a0 = { 568d3781c67409203f87fe5e5450 }


condition:
	$a0
}