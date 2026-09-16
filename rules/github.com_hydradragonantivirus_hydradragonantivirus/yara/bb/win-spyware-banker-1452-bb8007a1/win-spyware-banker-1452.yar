rule Win_Spyware_Banker_1452
{
strings:
	$a0 = { b37df7db1bfedf66637e642dcb4444686c2285367d71f926b1bc210267421f2226297297415bd5da8594ecffe3f6c618dd9dbb90366e005a90ceae0a8cedaf1a61b63bb5 }


condition:
	$a0
}