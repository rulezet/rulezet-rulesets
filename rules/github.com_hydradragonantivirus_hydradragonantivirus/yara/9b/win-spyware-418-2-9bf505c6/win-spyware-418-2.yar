rule Win_Spyware_418_2
{
strings:
	$a0 = { dd8867ff2e6d6361666565136f7787616451207e801373312e6b471c84fd1bb06b792d }


condition:
	$a0
}