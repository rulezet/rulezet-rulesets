rule Win_Trojan_Joan_3
{
strings:
	$a0 = { c999e82900b440b9e001e8210045b43ee81b00b44f }


condition:
	$a0
}