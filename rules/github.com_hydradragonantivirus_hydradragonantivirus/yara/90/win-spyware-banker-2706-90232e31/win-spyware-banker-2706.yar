rule Win_Spyware_Banker_2706
{
strings:
	$a0 = { 784da51070bf3bb4829d066d44b363add3a96180d186eb91fb47264d838eb2efd0d88a6ddc80ad74b30a8e0c60aef7b89e2e74253dbb643a17c28ab659269b3a993a09fb7a7c279db91eabbea7f1 }


condition:
	$a0
}