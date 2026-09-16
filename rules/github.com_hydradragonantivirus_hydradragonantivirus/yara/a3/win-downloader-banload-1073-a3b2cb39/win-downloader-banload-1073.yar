rule Win_Downloader_Banload_1073
{
strings:
	$a0 = { d9aeffa472e64b764651ddef5dad9f21b53770bc0b25fa499ffa98cb7439749045876a120c52f16b4c21158a1d5b3f735ed1ff249a269854099714a84d6fcc20f4912a00 }


condition:
	$a0
}