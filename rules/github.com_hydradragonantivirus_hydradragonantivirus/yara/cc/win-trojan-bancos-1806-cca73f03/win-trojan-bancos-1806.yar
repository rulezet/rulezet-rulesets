rule Win_Trojan_Bancos_1806
{
strings:
	$a0 = { 36bbcb51b9670ed906ae897bcdf0e8d1da32294e4afe7bf39002e2969cca3e245dbc8c83d81c9521308323b40bb7acfc666fd3930e505ec8e7d68061e7417aadf8e1664b68da }


condition:
	$a0
}