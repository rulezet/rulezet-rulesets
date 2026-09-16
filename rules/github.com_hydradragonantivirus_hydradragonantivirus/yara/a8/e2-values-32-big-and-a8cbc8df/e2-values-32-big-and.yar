rule E2_values__32_big_AND_
{
strings:
	$a0 = { 67452301[0-20]efcdab89[0-20]30d32e58[0-20]b89e4984[0-20]0957cfec[0-20]d800502e[0-20]00ffff00[0-20]0000ffff[0-20]ff0000ff[0-20]ffff0000[0-20]00ff00ff }

condition:
	$a0
}