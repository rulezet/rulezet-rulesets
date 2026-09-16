rule Win_Trojan_Bancos_1858
{
strings:
	$a0 = { e5a392f39501369d8cf0a9aea5d5a42316b26f3a56636063f8af47bf9aec38334530e92fd1fa49bee5d19c001e36b7a6e0fdb714303c5d552bc1d88512987de51c9e04eb691f }


condition:
	$a0
}