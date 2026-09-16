rule Win_Trojan_Agent_35520
{
strings:
	$a0 = { 67735c6e65306e5c }

	$a1 = { 5c4d61696c6572335c6f70656e737472 }

	$a2 = { 5c506b69785f436572742e706173 }


condition:
	$a0 and $a1 and $a2
}