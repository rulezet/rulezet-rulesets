rule Win_Trojan_MPC44_1
{
strings:
	$a0 = { 5d81ed1200061eb84144cd213d535074408cd8488ed8832e030040832e1200408e0612000e }


condition:
	$a0
}