rule Win_Dropper_Agent_34344
{
strings:
	$a0 = { 8d45bc50b101ba542c1413a1b0461413e8a8f3ffff8b55bcb8b0461413e853ebffffb8b0461413e8a1edffffe84cf4ffff33c05a5959648910682a2b14138d45bcba0d000000e8faeaffffc3 }


condition:
	$a0
}