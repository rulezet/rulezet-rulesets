rule Win_Downloader_Small_3298
{
strings:
	$a0 = { a68e6dc6bf5dcdb6f558b813029bec2345697f10481afc7ff035a8e702044e1f6800ece73e17a276e45cdb126438c3aebf3d359e436921903d86 }


condition:
	$a0
}