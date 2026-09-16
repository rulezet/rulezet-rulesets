rule Win_Downloader_Delf_976
{
strings:
	$a0 = { 846eef178c11d4bfc5868955c8f192edc731774769a6975880af9f1c05ef40c226b8eee2a891c9c2f824bace9290cd0ad36c79712756159e2a970a3de45ddf5ee435dfbc8378 }


condition:
	$a0
}