rule Win_Trojan_KeepSmiling_1
{
strings:
	$a0 = { 39be1100b9ca032bce280446e2fbf13a6c6b0b065af13c390649f1393e0649ed3af259590649ed42f3ba3a065a }


condition:
	$a0
}