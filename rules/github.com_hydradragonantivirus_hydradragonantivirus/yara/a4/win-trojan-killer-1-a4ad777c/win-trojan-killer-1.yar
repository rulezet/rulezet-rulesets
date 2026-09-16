rule Win_Trojan_Killer_1
{
strings:
	$a0 = { fc368b2d81ed03004444b8ffa033dbcd2150580681fbffa0741b5058b81f35fec0fec0cd21535b899ea0028c86a202 }


condition:
	$a0
}