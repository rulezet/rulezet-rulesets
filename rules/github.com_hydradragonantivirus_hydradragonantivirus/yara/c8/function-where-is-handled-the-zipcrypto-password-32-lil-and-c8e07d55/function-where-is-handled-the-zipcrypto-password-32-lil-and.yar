rule function_where_is_handled_the_ZipCrypto_password__32_lil_AND_
{
strings:
	$a0 = { 78563412[0-20]89674523[0-20]90785634 }

condition:
	$a0
}