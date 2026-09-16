rule Win_Trojan_Sarka_1
{
strings:
	$a0 = { 0752eb0f79fcbd7e8ef80932ffe9dcfee4f80f09f7e91bfeb8fa1ce0a5ad09ea791832011e }


condition:
	$a0
}