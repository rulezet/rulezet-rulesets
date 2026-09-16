rule Win_Trojan_Small_3778
{
strings:
	$a0 = { e3be0a0bc20178b6c24dcfbb027f680e27902c6bd73b444f30a5454e3699a1519a90cfe2288c974c2ec6c1fe59a04cf6618280f99d4afb3eddc00d802437c33564eb4cf7d63bcf3cd3c65229a93e }


condition:
	$a0
}