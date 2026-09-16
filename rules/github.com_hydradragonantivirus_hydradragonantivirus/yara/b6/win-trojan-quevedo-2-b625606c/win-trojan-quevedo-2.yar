rule Win_Trojan_Quevedo_2
{
strings:
	$a0 = { 02cd1681ed0b018db62401b900018bfeacd0c8aae2fa1b6d40047f0002f94b4b1b2d480469349b42699c1b2d2c }


condition:
	$a0
}