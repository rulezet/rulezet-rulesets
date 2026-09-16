rule Win_Trojan_BOO_9
{
strings:
	$a0 = { e4c706207c7800b402b77eb101b280cdce80bfbf01017558b80203b77cb105cdcebebe7fbfce7f }


condition:
	$a0
}