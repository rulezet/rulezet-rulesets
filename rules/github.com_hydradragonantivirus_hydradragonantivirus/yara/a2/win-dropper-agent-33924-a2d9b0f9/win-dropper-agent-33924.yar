rule Win_Dropper_Agent_33924
{
strings:
	$a0 = { 504e3c57a73e2f3ddac844259cd9ffa33d74962213765fb41fa478e3fbf922d3f3825e82059cb83a5d8eb5ad8d8ce9a653056a8309ecd93c73aa0053228c289a }


condition:
	$a0
}