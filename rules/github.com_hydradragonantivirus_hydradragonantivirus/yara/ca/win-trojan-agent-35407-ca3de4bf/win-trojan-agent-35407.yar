rule Win_Trojan_Agent_35407
{
strings:
	$a0 = { 939c53501bd80bd8400bc313d80bc323d8401bc3585b9d }

	$a1 = { 2f00006e746f736b726e6c2e657865 }


condition:
	$a0 and $a1
}