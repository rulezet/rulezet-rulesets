rule Win_Trojan_Prion_1
{
strings:
	$a0 = { 03fa0e1789ec83e4fefb500e1fb824258d961f02cd21b41a8d963d02cd21b44eb1278d962202cd21730358cd21 }


condition:
	$a0
}