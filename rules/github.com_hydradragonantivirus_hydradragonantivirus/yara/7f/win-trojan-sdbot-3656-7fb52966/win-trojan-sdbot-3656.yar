rule Win_Trojan_SdBot_3656
{
strings:
	$a0 = { 7a777846fecd0707cc6c44102f4b2b525d9ae0c9c68a18bb8a9cf8d4068cbed89937c5adaef38632039aefdb036bf6a0a7e13c5aea6b9cc732bf00a14f2f3924fef2ea7316a4a1c2b969ca183514 }


condition:
	$a0
}