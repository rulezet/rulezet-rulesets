rule Win_Dropper_Agent_35455
{
strings:
	$a0 = { 75737031305f6b696c6c2e646c6c }

	$a1 = { 7461736b6b696c6c[0-14]6176702e657865 }

	$a2 = { 5c447269766572735c626565702e737973 }


condition:
	$a0 and $a1 and $a2
}