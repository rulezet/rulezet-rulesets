rule Win_Trojan_Mouse_2
{
strings:
	$a0 = { 40008ed8e828002505008bc8bb1c002ea1a900890783c30283fb3f7203bb1e00891e1c00e2e9 }


condition:
	$a0
}