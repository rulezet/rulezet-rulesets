rule Win_Trojan_DSME_3
{
strings:
	$a0 = { 4c5346f8d2484108263045b05479ffb350f63f95c94cc648c954c848bf003e06 }


condition:
	$a0
}