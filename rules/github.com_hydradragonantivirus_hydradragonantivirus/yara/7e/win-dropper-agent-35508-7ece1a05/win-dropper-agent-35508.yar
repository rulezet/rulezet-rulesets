rule Win_Dropper_Agent_35508
{
strings:
	$a0 = { 13c183c262c1d2043915c0f65300740e33ca81 }


condition:
	$a0
}