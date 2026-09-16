rule Win_Trojan_Agent_34127
{
strings:
	$a0 = { 5081f08218ad335881c648733c }


condition:
	$a0
}