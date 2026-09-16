rule Win_Trojan_L_21
{
strings:
	$a0 = { 41018a073206060188074381fb7c03740f8a0732060701 }


condition:
	$a0
}