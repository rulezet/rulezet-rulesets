rule Win_Trojan_TempVir_1
{
strings:
	$a0 = { c802585003e88b5e00b80242cd21721dbdc802585003e88b5e00b9cd0281e9fb005a5281c20001 }


condition:
	$a0
}