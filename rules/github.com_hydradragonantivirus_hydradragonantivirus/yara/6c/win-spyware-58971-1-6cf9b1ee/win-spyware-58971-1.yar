rule Win_Spyware_58971_1
{
strings:
	$a0 = { ebffff53558b6c24148bc7992bc2568bf08bc79983e20f }

	$a1 = { 68616d6d696e670065706f696e745f78 }


condition:
	$a0 and $a1
}