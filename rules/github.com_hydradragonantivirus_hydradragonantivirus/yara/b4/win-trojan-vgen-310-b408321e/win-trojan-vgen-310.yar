rule Win_Trojan_VGEN_310
{
strings:
	$a0 = { c9ba2e01cd2150be7801b95c00bd0001bfd401e827015bbad401b440cd21b43ecd21b409ba3801cd21cd203430 }


condition:
	$a0
}