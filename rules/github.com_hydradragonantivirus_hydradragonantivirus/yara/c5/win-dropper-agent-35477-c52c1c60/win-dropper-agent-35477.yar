rule Win_Dropper_Agent_35477
{
strings:
	$a0 = { 71178bc88d05512f8501f7d23cf981c0e92ff1018b }


condition:
	$a0
}