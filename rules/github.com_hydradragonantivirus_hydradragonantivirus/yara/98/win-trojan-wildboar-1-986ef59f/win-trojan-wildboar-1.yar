rule Win_Trojan_WildBoar_1
{
strings:
	$a0 = { 0e80dadb89fa3a57ef0e1f1a51c188d63af42a55d480ce5981fd5ff40781ddf59a2bee80ca590be926fe062c0080 }


condition:
	$a0
}