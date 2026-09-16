rule Win_Trojan_ExeHeader_9
{
strings:
	$a0 = { 0200ba80002bc28ec0bf00018bf7b99001fcf3a550b4ffcd210ac075351f1eb82135cd21891e38028c063a02b020cd }


condition:
	$a0
}