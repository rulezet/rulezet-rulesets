rule Win_Dropper_Agent_34171
{
strings:
	$a0 = { 6a01e8eddaffff6a01e8e6daffff6a01e8dfdaffff6a01e8d8daffff6a01e8d1daffff6a01e8cadaffff6a01e8c3daffff8d45e8bae8654000e84ed3ffff }


condition:
	$a0
}