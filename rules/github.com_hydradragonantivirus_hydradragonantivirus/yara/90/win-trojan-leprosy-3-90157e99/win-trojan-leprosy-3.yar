rule Win_Trojan_Leprosy_3
{
strings:
	$a0 = { 52018a2f322e0a01882f4381fb6c067ef159c3b440cd21c38b1e0002fe065201803e5201147e }


condition:
	$a0
}