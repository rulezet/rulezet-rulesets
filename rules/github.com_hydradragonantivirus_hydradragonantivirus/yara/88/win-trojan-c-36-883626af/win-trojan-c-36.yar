rule Win_Trojan_C_36
{
strings:
	$a0 = { 7a01b409ba3502cd215533ed32e4cd163c0d740d458886a4028ad0b402cd21ebeb8bcd5db409ba5802cd21be5b02 }


condition:
	$a0
}