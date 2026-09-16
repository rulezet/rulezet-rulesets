rule Win_Spyware_3919_1
{
strings:
	$a0 = { 53568bf35e0f00cb568b5c240483c40883d879e84c020000d4be33f3e67f }


condition:
	$a0
}