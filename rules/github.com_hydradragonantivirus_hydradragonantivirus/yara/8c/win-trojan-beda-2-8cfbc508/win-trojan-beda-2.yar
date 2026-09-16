rule Win_Trojan_Beda_2
{
strings:
	$a0 = { eb06b91800cd21eb13b8024233c933d2cd21b9fa0590ba1001e82b01b80157b9dabe8b16b9 }


condition:
	$a0
}