rule Win_Trojan_Mini3_4
{
strings:
	$a0 = { 80fc43742280fc56741d80fc6c74183d35f075049d33c0cf3d35f1750ebadf010e1fe817009dcf }


condition:
	$a0
}