rule Win_Trojan_Boot_1
{
strings:
	$a0 = { 140058595a5b5e075f1f9d2eff36ae002eff368000cbb00132f6b901009c0ee8e9ffc3 }


condition:
	$a0
}