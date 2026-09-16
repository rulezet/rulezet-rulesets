rule Win_Trojan_Agent_35448
{
strings:
	$a0 = { 558bec81c4c4feffffe802000b57e8020007350bc075 }

	$a1 = { 53656c6644656c2e626174 }

	$a2 = { 656c656d656e74636c69656e742e657865 }


condition:
	$a0 and $a1 and $a2
}