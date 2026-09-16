rule Win_Trojan_Swastika_1
{
strings:
	$a0 = { ba01ba0001b440cd215951b440bafeffcd21730ab800429933c9cd21ebeb59bed0fe8b4c168b54 }


condition:
	$a0
}