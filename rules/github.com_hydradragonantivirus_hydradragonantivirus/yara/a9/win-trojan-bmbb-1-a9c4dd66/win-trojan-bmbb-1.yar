rule Win_Trojan_BMBB_1
{
strings:
	$a0 = { 0efc03e8caffb440b9fe02ba0001cd218b0ef903890efc03b80242e8b5ffb440b9fe0289f2cd21 }


condition:
	$a0
}