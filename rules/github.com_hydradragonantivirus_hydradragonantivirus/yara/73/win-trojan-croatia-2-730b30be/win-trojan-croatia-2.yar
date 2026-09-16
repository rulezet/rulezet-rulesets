rule Win_Trojan_Croatia_2
{
strings:
	$a0 = { 5b81eb4501891e1601b42acd2181f9c907770580fe017300b4eecd2181f966067503e98000 }


condition:
	$a0
}