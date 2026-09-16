rule Win_Trojan_Mururoa_2
{
strings:
	$a0 = { 24e205eb1b5eeb1a3014eb11b92200eb068a945209ebf581c65309ebeb46ebe1ebbb56ebec90eb }


condition:
	$a0
}