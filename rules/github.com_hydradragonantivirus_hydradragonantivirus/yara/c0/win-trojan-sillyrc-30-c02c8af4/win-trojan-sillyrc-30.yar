rule Win_Trojan_SillyRC_30
{
strings:
	$a0 = { 3d004b740b80fcff7402ebefb8f0f0cf9c50535152565706 }


condition:
	$a0
}