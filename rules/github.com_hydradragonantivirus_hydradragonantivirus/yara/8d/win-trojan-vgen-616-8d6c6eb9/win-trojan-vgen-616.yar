rule Win_Trojan_VGEN_616
{
strings:
	$a0 = { 2c0133d28eda8ec2be04008bfead50ad50b83101ab8cc8ab0e1fb95705be0c02fec6529dace2fdcd20561be9d6 }


condition:
	$a0
}