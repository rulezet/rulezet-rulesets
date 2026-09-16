rule Win_Dropper_Agent_35656
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d }

	$a1 = { 332d364d1b246924e9 }

	$a2 = { 3c30323f0958521b790a5542 }


condition:
	$a0 and $a1 and $a2
}