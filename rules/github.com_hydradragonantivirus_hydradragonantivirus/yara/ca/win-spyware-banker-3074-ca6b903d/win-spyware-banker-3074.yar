rule Win_Spyware_Banker_3074
{
strings:
	$a0 = { 98d735f4022cd603f3d6d80ae86b77a554c427162f500653fda9d2d71f3bcd671522390e6393ed78b9bc9b0b36f90b915ca9fbee947e2e1363c3d4e48a62 }


condition:
	$a0
}