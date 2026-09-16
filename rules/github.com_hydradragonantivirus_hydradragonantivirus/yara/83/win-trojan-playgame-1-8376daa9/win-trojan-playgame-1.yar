rule Win_Trojan_PlayGame_1
{
strings:
	$a0 = { 204d4b202f2054726964656e54205de800005e83ee13bf0001fce823050e0e1f07b430cd213c04721c3dadde7417b802fecd213dfd01740db8e433cd2180fc }


condition:
	$a0
}