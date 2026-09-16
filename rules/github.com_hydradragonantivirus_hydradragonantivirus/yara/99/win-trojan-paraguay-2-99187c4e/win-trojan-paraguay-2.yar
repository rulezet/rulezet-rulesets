rule Win_Trojan_Paraguay_2
{
strings:
	$a0 = { e800005d81ed04018d9e6f03c686b60400e84402bf00018db68f03fca5a5c786ae0407008b868d030186ae04b802fa }


condition:
	$a0
}