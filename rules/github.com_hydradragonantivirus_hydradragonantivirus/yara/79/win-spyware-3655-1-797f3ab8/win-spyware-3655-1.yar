rule Win_Spyware_3655_1
{
strings:
	$a0 = { 578d3a81c7b845462b87d75f52812c24b845462b5af5 }


condition:
	$a0
}