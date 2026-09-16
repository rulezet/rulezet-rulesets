rule Win_Dropper_CoreFlood_1
{
strings:
	$a0 = { f3c9d9dde9a0a8e8f9bd667a714f563422390f5657e1e1f7d0cbb4cec2d055 }

	$a1 = { 75770bff7415ff37c707657865 }


condition:
	$a0 and $a1
}