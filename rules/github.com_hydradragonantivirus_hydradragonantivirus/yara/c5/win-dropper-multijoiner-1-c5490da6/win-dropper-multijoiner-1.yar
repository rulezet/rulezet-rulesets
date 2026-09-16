rule Win_Dropper_MultiJoiner_1
{
strings:
	$a0 = { 0f209d10b404ecc592cd1e071fcc06c61b589728100706e90608595ec41028f8f67f20e9570c636f62616e326b21180e }


condition:
	$a0
}