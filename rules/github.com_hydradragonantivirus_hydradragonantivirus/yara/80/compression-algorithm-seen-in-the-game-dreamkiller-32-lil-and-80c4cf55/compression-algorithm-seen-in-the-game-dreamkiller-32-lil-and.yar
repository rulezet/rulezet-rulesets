rule compression_algorithm_seen_in_the_game_DreamKiller__32_lil_AND_
{
strings:
	$a0 = { 1fffffff[0-20]3fffffff[0-20]0fffffff }

condition:
	$a0
}