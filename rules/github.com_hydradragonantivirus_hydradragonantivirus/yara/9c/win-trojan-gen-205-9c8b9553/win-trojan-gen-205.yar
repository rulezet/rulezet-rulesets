rule Win_Trojan_Gen_205
{
strings:
	$a0 = { 59ff46fc817efc6c537cbb5f5e8be55dc3558bec81eca80556578b7e04b80f0150e80303 }


condition:
	$a0
}