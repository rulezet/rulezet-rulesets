rule Win_Trojan_Pokusny_1
{
strings:
	$a0 = { 57bf7c051e57bf86051e579ab202a101bf38051e57bf8c081e57b8ff00509a5307da018d }


condition:
	$a0
}