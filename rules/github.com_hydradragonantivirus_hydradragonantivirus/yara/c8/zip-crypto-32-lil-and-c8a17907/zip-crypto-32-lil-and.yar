rule Zip_Crypto__32_lil_AND_
{
strings:
	$a0 = { 05840808[0-20]78563412[0-20]89674523[0-20]90785634 }

condition:
	$a0
}