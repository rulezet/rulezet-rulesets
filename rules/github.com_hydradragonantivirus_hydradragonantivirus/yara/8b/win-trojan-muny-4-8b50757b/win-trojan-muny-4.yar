rule Win_Trojan_Muny_4
{
strings:
	$a0 = { bf88048e4317c04315464ab705ef4a06b347be25078a910706ca26753734f8b3478d8425 }


condition:
	$a0
}