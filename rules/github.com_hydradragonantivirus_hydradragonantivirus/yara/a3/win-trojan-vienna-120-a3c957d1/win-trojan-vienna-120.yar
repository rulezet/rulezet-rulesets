rule Win_Trojan_Vienna_120
{
strings:
	$a0 = { b95a02ba????8bea4d8a46004d8a66002ae0886600e2f5 }


condition:
	$a0
}