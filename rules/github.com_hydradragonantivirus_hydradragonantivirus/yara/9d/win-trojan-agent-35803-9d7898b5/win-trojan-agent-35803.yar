rule Win_Trojan_Agent_35803
{
strings:
	$a0 = { 558bec83ec5456e882feffffe81ffeffff68d0070000ff154010400033f66a448d45ac5650e84a }


condition:
	$a0
}