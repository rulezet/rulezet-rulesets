rule Win_Trojan_Radyum_6
{
strings:
	$a0 = { 01e80500eb239000008db636018bfeb9e60090ad33861401abe2f8c351e8e9ff59b440cd21 }


condition:
	$a0
}