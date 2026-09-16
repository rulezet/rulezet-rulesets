rule Win_Trojan__0361_0001_001_1
{
strings:
	$a0 = { 405a59cd21e83800b440b9440290ba0001cd21b801578b36fd028b54188b4c16cd21b43ecd21b8 }


condition:
	$a0
}