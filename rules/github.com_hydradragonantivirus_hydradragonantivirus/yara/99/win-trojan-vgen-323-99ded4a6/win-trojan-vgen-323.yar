rule Win_Trojan_VGEN_323
{
strings:
	$a0 = { 638beefcada30001aca20201b9e41881e9a70281c6250003f1bbe4178d38fdf3a447ffe74f8d8c01fff3a48bf581 }


condition:
	$a0
}