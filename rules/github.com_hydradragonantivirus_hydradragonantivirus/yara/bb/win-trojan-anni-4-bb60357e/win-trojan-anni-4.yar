rule Win_Trojan_Anni_4
{
strings:
	$a0 = { 5b81eb8b018db7ac01e80200eb13b9cf008bfeba390aad33c2f7d2ab03d2e2f6c358e28cebbba9df1e9b4bd7b982a62b57b0833c7667c72784e89915caab960e8f42beaa1eb0102aaa }


condition:
	$a0
}