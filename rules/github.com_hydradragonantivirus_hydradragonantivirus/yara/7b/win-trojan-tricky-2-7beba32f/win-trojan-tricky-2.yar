rule Win_Trojan_Tricky_2
{
strings:
	$a0 = { 0200eb94b640b903008ae68d96ee01cd21b8024233c933d2cd21b640b9ec008ae68d960301cd21 }


condition:
	$a0
}