rule Win_Trojan_Zmiana_3
{
strings:
	$a0 = { ac055033c050cb44039025f0ff8bf8b9a20090be7e01fcf3a58bd8b104d3eb8cd903d95333db53cb0e01504b4c }


condition:
	$a0
}