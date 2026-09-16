rule Win_Trojan_JS_274
{
strings:
	$a0 = { 61742869297d723d722b73313b7d }

	$a1 = { 65283130312c3131382c3937292b226c }

	$a2 = { 2b7a32353633622b637a323536332b7a3235 }


condition:
	$a0 and $a1 and $a2
}