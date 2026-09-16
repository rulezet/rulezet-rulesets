rule Win_Trojan_Small_5337
{
strings:
	$a0 = { 7770ce3bdd86b1aa3b0d6c1c7c15576b0f055a37466ef66ad57f92971fc9bbd30d496cd9fcb05a07d4ce58ce7a68e53bf9232a90c4ff785fd3b23e5b95636ce7d9 }


condition:
	$a0
}