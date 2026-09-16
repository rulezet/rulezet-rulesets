rule Win_Trojan_Peed_164
{
strings:
	$a0 = { f7db87da75705589e55389e38d61045089dc5b89d88b5d086bdb0383eb0bc9c2 }


condition:
	$a0
}