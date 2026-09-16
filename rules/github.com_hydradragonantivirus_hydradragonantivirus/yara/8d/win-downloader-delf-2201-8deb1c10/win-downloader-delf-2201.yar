rule Win_Downloader_Delf_2201
{
strings:
	$a0 = { 88bd1a903265188c4ba514622634222f281c1208f25168ee382c8f393244bbdb1df8f40866a9beaacc97c5c1cd592b80cb0d5637ccb1403fee906fba71dacdb46cab666b94042cee5ad7d9e6f66342c4 }


condition:
	$a0
}