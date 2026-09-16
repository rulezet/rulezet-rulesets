rule Win_Trojan_Win95_1
{
strings:
	$a0 = { bbcb00cd25587258b86c7133db4333c9ba1200be9e00cd21724693b440bacb00b90060cd21 }


condition:
	$a0
}