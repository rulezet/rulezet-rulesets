rule Win_Trojan_W_393
{
strings:
	$a0 = { 03f3e8ecf5ffff5b5a5933ff648b7f2003c732c422855f0e41008bf203f300263006282646e2f761c300c3 }


condition:
	$a0
}