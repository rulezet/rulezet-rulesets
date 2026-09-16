rule Win_Trojan_Cheeba_5
{
strings:
	$a0 = { 01902e8035124781ff680772f5 }


condition:
	$a0
}