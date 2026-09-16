rule Win_Trojan_Vienna_102
{
strings:
	$a0 = { 02890db440b9f4028bd681ea530290cd2172213df402751cb80042ba0000b9000090cd2172 }


condition:
	$a0
}