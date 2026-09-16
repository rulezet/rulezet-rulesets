rule Win_Dropper_Agent_35617
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d0001642800eb }


condition:
	$a0
}