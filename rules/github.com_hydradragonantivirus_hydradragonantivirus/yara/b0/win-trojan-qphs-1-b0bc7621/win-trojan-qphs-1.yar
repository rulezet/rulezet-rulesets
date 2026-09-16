rule Win_Trojan_QPHS_1
{
strings:
	$a0 = { 8ed08ec08ed8b8007c8be0fbcd12c1e0062d0001a3317c068ec0b80702b90900ba800033dbcd1307ff2e2f7c8101 }


condition:
	$a0
}