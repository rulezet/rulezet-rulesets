rule Win_Trojan_Agent_33556
{
strings:
	$a0 = { 20da2aa886536b4cdcbf18e81eeb520a065b5542f8e27deb32449a849cd7f3a18cca6e5ca2caadb82f4b2f856fce5d23441ff58974a6983ae6df66dbbfab1a5c746554e28a33bf26d8b1c30f398239130726 }


condition:
	$a0
}