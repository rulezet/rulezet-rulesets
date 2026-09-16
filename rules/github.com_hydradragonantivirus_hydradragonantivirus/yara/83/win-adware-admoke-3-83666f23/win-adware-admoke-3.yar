rule Win_Adware_Admoke_3
{
strings:
	$a0 = { 8d45e0bab0604b00e82aeaf4ffa114604d00e8d4cbffff84c0740e8d45e08b1514604d00e80eeaf4ff }


condition:
	$a0
}