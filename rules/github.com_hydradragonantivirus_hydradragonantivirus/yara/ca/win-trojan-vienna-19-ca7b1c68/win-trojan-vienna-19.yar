rule Win_Trojan_Vienna_19
{
strings:
	$a0 = { 83c638b90300bf0001f3a45eb41a8bd683c20dcd21ba010003d6b44eb90000cd21eb04b44fcd21 }


condition:
	$a0
}