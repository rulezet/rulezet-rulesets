rule Win_Downloader_Swizzor_481
{
strings:
	$a0 = { 16adc32deefc3e99fef910249a45d66ba7e3a061d842288239370f6ebef658a9c26518f73b7aff34360daaf2176a67adeeafa18762b00cb636b90b9769bad1cc2b679d37b7beea11f7ade89e71d2 }


condition:
	$a0
}