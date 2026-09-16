rule Win_Dropper_Agent_34680
{
strings:
	$a0 = { 656c656f6e6f722e657865 }

	$a1 = { 64656c20633a5c31312e626174[0-51]6f70656e }

	$a2 = { 7a6f6f68616e2e646c6c }


condition:
	$a0 and $a1 and $a2
}