rule Win_Trojan_Vienna_122
{
strings:
	$a0 = { b91603ba????8bea4d8a46004d8a66002ae0886600e2f5 }


condition:
	$a0
}