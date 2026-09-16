rule Win_Trojan_Sense_1
{
strings:
	$a0 = { 03b8023de84bff7321b43cb90300cd21721c8bd8e82200b440ba3903b9070290cd21ba5f00b8 }


condition:
	$a0
}