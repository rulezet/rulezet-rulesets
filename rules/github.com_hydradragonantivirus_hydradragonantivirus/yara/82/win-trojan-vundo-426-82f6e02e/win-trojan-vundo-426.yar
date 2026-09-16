rule Win_Trojan_Vundo_426
{
strings:
	$a0 = { 668105eb120110ac9d0f8c9f000000e86500000098e858bff188490dd6ec6e2b573be8cd44f63f6a2dc3dc }


condition:
	$a0
}