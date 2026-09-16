rule Win_Trojan_Mybot_8270
{
strings:
	$a0 = { 2988a984a5cf048f205b0b79f25a06a2d4687138946ad6140edd9ed907da32132b5895d75f3031c954ecca8cacd1be3381dc7ccab2c32fb9d089b71e443b4bd07aae98398d82 }


condition:
	$a0
}