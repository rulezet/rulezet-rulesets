rule Win_Trojan_Click_2
{
strings:
	$a0 = { cd213d7ffe75180e0e1f07be00018bfe8bc603364702b949019050fcf3a4c3832e020078a102002d10008ec08c }


condition:
	$a0
}