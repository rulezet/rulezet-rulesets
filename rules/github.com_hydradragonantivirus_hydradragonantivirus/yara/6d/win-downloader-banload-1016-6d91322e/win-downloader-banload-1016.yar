rule Win_Downloader_Banload_1016
{
strings:
	$a0 = { 4ed30ed73a3524843ef181c24d4058dc709462b58f3bac3c5baefa2a640896839e96dd645c2132251f4348656b3f467cc5dbefc7fa87f72da08d68f639d0b39d }


condition:
	$a0
}