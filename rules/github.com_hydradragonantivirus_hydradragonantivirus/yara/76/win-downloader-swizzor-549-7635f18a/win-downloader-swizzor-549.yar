rule Win_Downloader_Swizzor_549
{
strings:
	$a0 = { 0778f75b149fc123338e964b1a61b1df0388b7174f226a5a8899ebac1c7cdaec8138c80b97d36b541423297815c01db5 }


condition:
	$a0
}