rule Win_Trojan_Lazy_1
{
strings:
	$a0 = { 840026a186008ec0268b07bb905029 }


condition:
	$a0
}