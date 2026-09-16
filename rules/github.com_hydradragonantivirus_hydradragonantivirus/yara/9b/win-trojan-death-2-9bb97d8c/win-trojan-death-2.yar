rule Win_Trojan_Death_2
{
strings:
	$a0 = { fb04fcb9eb01813585db83c70383ef01e2f46ddb858604369cdab61b0b0341dd15dbab5703f880f50c5da4de084d73 }


condition:
	$a0
}