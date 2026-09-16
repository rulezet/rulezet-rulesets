rule Win_Trojan_Code_3
{
strings:
	$a0 = { 1e0a02b95001ba50fdcd21b43ecd21b801438a0e15 }


condition:
	$a0
}