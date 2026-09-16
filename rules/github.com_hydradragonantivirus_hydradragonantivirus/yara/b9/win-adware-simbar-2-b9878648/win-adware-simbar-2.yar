rule Win_Adware_Simbar_2
{
strings:
	$a0 = { 558bec6aff681082400068845b400064a1 }

	$a1 = { 5c00000064656c73656c662e626174 }

	$a2 = { 6a7676723c3131756b6f72 }

	$a3 = { 5c5574696c6974795c }


condition:
	$a0 and $a1 and $a2 and $a3
}