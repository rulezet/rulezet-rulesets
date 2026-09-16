rule Win_Trojan_Monster_2
{
strings:
	$a0 = { 061901feeb00c606190100b82425bad401cd21b41aba5b02cd21b44eb92700ba0d01cd21726eeb06b44fcd217266b8 }


condition:
	$a0
}