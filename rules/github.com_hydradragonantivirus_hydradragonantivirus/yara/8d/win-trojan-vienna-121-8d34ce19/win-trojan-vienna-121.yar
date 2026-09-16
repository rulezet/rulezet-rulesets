rule Win_Trojan_Vienna_121
{
strings:
	$a0 = { b96302ba????8bea4d8a46004d8a66002ae0886600e2f5 }


condition:
	$a0
}