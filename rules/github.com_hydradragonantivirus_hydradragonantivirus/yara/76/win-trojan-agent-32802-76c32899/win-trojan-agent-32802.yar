rule Win_Trojan_Agent_32802
{
strings:
	$a0 = { 33c53d1b71d2f55b4fbbde277d642a4eb352bd615175c83055d0ddfabdf1aa7a261aed364acf6211e9b11a92d4815836b48183b1f589e8178d32b3c770c3aa31f9 }


condition:
	$a0
}