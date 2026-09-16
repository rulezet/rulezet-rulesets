rule Win_Trojan_Bancos_709
{
strings:
	$a0 = { 0a49a9c8fd2b36da31b735976142a48e340f830e54e1042bdccd54cba62a669f56d02ca6251dd011f5110584e34e7c443fe7908a503697257accd280b0daaa6685 }


condition:
	$a0
}