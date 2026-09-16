rule Win_Trojan_Fantasma_1
{
strings:
	$a0 = { 038bc580ec02ba000150e8fffd5f72242bc875118bc599e8f2fd720997b118bae804e8e7fd58 }


condition:
	$a0
}