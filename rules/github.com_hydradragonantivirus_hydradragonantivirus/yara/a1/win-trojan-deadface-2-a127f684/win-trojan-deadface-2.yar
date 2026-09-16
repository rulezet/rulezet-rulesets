rule Win_Trojan_DeadFace_2
{
strings:
	$a0 = { 0103bb007ccdca36a113044836a31304bb4000f7e350500733ffbe007cb90002f3a533c08ec0bf }


condition:
	$a0
}