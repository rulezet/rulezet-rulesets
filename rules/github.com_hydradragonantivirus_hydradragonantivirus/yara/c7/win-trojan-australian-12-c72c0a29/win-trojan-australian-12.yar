rule Win_Trojan_Australian_12
{
strings:
	$a0 = { e930056a033bc473698bc42d44039025f0ff8bf8b9a20090be7e01fcf3a58bd8b104d3eb8cd903d95333db53cb0e01 }


condition:
	$a0
}