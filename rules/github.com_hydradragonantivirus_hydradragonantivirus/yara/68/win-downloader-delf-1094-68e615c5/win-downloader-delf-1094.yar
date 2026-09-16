rule Win_Downloader_Delf_1094
{
strings:
	$a0 = { cc978ac6d37c631e6ffd52f283078dfe32e8aa99160e06601c5fc6634ad1388bb8dedc507d023f757fb8b3875612abd55a0989c170b20df1656c99493fd6bad1ade84deab3e36d1b3b6ba8f195a0b1fc }


condition:
	$a0
}