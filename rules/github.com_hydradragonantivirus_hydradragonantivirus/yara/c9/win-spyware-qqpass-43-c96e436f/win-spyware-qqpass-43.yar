rule Win_Spyware_QQPass_43
{
strings:
	$a0 = { 68f84d400053e801f2ffff89c785f6745385ff744f6a006a006a006a006a006a00a150664000506a00badc4d4000b8d44d4000 }


condition:
	$a0
}