rule Win_Downloader_Zlob_2307
{
strings:
	$a0 = { c2602d44c47dfedb6be2f7acd6adee513a6bf716d371adbc695afb2e58c4e09a411a63e183696b4f7824d20d7df0f483787b66830480ba33f629f9df30c4bb0807242f07f9d0a164fc6a393ead00 }


condition:
	$a0
}