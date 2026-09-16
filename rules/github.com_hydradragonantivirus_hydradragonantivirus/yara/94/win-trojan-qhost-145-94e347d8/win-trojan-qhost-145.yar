rule Win_Trojan_Qhost_145
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d00005ab000eb2683fe0174 }

	$a1 = { 2573257325642e6c6f67 }

	$a2 = { 47455420257320485454502f312e31 }


condition:
	$a0 and $a1 and $a2
}