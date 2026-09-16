rule Win_Trojan_Vienna_124
{
strings:
	$a0 = { 5051be????fc5683c6??90bf0001b90300f3a45eb430cd21 }


condition:
	$a0
}