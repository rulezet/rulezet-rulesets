rule Win_Trojan_Agent_35463
{
strings:
	$a0 = { 2f2e6463632073656e64[0-18]5c696d706f7274616e742e7478742e766273 }


condition:
	$a0
}