rule Win_Dropper_Agent_34177
{
strings:
	$a0 = { bf001040008bc705c1030000ffd0e907ffffff }


condition:
	$a0
}