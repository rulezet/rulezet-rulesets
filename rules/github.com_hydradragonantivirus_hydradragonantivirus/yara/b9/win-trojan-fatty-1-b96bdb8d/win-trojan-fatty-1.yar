rule Win_Trojan_Fatty_1
{
strings:
	$a0 = { d40bfce8fe00be8400bfc00be82505be4c00bfcc0be81c05e80d01b456fecccd170f848600eb16902ea1d40b8e }


condition:
	$a0
}