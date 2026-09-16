rule Win_Trojan_CyberSpy1_1
{
strings:
	$a0 = { 603260f5fb6d1d16aa514389e16367c70401c80091f46ac230587b656570a18bb59b140078a018beb2488c4decd457e60d3f }


condition:
	$a0
}