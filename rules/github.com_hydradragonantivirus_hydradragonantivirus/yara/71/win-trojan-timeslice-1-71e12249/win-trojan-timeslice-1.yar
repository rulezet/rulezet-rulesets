rule Win_Trojan_Timeslice_1
{
strings:
	$a0 = { 8ec64e8edec74501080009c97505816d12c3001f8bf5bf }


condition:
	$a0
}