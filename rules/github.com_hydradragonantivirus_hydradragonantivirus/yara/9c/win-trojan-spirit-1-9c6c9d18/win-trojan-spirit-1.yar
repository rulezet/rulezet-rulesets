rule Win_Trojan_Spirit_1
{
strings:
	$a0 = { 33ff8ed7bc007c8edfbe14044ee8ffff0cadb106d3e08ec0b8eb3cab5e83ee11bf3e00fcb9d900 }


condition:
	$a0
}