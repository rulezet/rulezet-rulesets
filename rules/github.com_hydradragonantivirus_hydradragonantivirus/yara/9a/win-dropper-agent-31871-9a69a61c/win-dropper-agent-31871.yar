rule Win_Dropper_Agent_31871
{
strings:
	$a0 = { 8b45fcba402d1413e847ebffff755db8502d1413e85ff5ffff3c01754f }


condition:
	$a0
}