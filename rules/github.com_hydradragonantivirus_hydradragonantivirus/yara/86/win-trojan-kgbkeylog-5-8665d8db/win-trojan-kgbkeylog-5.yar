rule Win_Trojan_KGBKeylog_5
{
strings:
	$a0 = { 4883ec28e8872000004883c428e90efdffffcccccccccccccccccccccccccccc48894c }

	$a1 = { 5c5265666f674d6f6e69746f725c4d706b3634 }


condition:
	$a0 and $a1
}