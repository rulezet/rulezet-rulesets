rule Win_Trojan_Rukap_83
{
strings:
	$a0 = { 2806081fd6eb6792c8e8762253a275baaf34e676d01863730a5a5f02c25bc6b7b45b7d5801439182fa40e4a65050e36edda3b1f85abc460937e5f324ab4da1e2e2 }


condition:
	$a0
}