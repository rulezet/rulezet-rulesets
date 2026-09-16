rule Win_Trojan_Brasil_2
{
strings:
	$a0 = { 0102bb0002b90100ba8000cd13813ea803cfcf7441b80103b103cd13bfb801beb803 }


condition:
	$a0
}