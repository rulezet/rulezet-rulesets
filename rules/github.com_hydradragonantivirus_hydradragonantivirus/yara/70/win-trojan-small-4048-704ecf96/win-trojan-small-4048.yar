rule Win_Trojan_Small_4048
{
strings:
	$a0 = { 5755e87f00000029ed81c500????fff7dd01cd89ef81c7ef0785f581ef480085f583c715518b0c246a006affe82c0000008d88dd1111dd29 }


condition:
	$a0
}