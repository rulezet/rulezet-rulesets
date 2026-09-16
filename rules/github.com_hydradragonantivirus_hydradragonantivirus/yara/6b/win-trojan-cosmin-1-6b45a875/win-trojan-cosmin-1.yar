rule Win_Trojan_Cosmin_1
{
strings:
	$a0 = { 123d80027402cd2033db068ec3bb1304268b3f07bdae0581ef80028bc780c425033e010103ef8b }


condition:
	$a0
}