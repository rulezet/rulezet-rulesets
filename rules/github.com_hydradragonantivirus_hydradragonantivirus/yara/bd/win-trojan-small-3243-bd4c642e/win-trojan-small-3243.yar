rule Win_Trojan_Small_3243
{
strings:
	$a0 = { 8b75088d45fc506a0068000100006a228d45f4506a0056ff15e00e01008bd885db7c3d }


condition:
	$a0
}