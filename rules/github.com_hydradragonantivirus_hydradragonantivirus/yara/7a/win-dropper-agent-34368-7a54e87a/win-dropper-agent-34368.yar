rule Win_Dropper_Agent_34368
{
strings:
	$a0 = { 55e82000000068f11440006802154000e8ccffffffe8f1fbffff33f6e891feffffe843ffffff }


condition:
	$a0
}