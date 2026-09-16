rule Win_Trojan_Stoned_8
{
strings:
	$a0 = { 1fb8010333db9c26ff1e1f00bb0002b80103b9060080fa807305b90200b6019c26ff1e1f00 }


condition:
	$a0
}