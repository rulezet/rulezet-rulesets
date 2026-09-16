rule unlzx_table_three__16_lil_32_
{
strings:
	$a0 = { 00000100030007000f001f003f007f00ff00ff01ff03ff07ff0fff1fff3fff7f }

condition:
	$a0
}