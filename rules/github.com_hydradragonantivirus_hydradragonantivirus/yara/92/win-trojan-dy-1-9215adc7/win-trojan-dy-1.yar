rule Win_Trojan_Dy_1
{
strings:
	$a0 = { 4000be8000ff344646e2fab44e33c9ba3c01cd217210803e9e00fa7303e81d00b44fcd2173f0b94000befe008f044e }


condition:
	$a0
}