rule Win_Trojan_Autorun_351
{
strings:
	$a0 = { 5b4175746f52756e5d0d0a6f70656e3d75636d756c6a762e657865 }


condition:
	$a0
}