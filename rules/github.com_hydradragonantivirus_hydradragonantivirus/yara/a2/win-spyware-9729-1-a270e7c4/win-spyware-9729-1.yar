rule Win_Spyware_9729_1
{
strings:
	$a0 = { 98e8c0050000caa9670129b75e8146b0 }


condition:
	$a0
}