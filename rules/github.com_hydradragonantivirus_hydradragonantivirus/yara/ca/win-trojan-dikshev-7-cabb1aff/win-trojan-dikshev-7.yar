rule Win_Trojan_Dikshev_7
{
strings:
	$a0 = { 408bd533c9b9533381e93232cd21b8ff422cff33c933d2cd215eb0e8578bfeaa5f5683c63683ee }


condition:
	$a0
}