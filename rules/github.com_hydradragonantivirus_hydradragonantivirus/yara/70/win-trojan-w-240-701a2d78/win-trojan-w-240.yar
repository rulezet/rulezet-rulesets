rule Win_Trojan_W_240
{
strings:
	$a0 = { 5aa3f29232cfc6198369b1c72622c411705450a20bce67bce79b1cf27b3de672d4cacd0e5a221d11105f19684244a484 }


condition:
	$a0
}