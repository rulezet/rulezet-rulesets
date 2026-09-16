rule Win_Trojan_Form_9
{
strings:
	$a0 = { 060026a11304d3e08ec033ffb1fffcf3a506b89a0050b80102bbfe018b164f008b0e4d00cd13 }


condition:
	$a0
}