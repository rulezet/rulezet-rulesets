rule Win_Trojan_Delf_938
{
strings:
	$a0 = { 89c309db7448b8005b14138b15c4451413e81ee7ffffa1045c1413e8a8daffff89c6a1045c14135089f189dab8005b1413e89ae7ffff89f0e8dffbffff89f0e89cdaffffb8005b1413e872e7ffff }


condition:
	$a0
}