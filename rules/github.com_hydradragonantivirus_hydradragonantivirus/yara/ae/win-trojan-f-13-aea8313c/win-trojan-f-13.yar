rule Win_Trojan_F_13
{
strings:
	$a0 = { be82002e8a242e322651008bdb2e8824468bdb81fe680375ea585e8bdbc3 }


condition:
	$a0
}