rule Win_Trojan_Dreg_3
{
strings:
	$a0 = { 0400cc8d9ec802ffd35724dacdce8c69e3ed8871efed8851eeedfa18dc18dc148d7943eeb8cb252221f10762b6d001 }


condition:
	$a0
}