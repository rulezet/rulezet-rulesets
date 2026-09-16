rule Win_Trojan_Agent_35761
{
strings:
	$a0 = { 434c5349445c7b33[0-67]5c3132332e696e666f }

	$a1 = { 7265722e6578650073656e64 }


condition:
	$a0 and $a1
}