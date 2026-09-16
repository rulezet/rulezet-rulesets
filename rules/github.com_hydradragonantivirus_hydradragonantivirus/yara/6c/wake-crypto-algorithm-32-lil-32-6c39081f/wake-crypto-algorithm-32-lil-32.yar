rule Wake_crypto_algorithm__32_lil_32_
{
strings:
	$a0 = { 3b8f6a725c3b9ae6e51fc7d3d2733cabb38e3a4de8d696037a2f4c3df37ce29e }

condition:
	$a0
}