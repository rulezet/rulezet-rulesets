rule Win_Adware_Casino_22
{
strings:
	$a0 = { e81605d7dfe91604e420558bec81ec28 }

	$a1 = { 475f434153494e4f5f494e464f }

	$a2 = { 2f646f776e6c6f61646661696c2e617370 }


condition:
	$a0 and $a1 and $a2
}