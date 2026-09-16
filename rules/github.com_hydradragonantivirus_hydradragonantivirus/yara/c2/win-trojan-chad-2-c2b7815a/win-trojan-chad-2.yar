rule Win_Trojan_Chad_2
{
strings:
	$a0 = { 0300894408b440b9ed028b14cd21b8004233c933d2cd21b440b9030089f783c70989facd21b801 }


condition:
	$a0
}