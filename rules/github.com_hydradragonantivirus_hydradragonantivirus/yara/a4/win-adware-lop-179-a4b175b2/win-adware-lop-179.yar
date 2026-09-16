rule Win_Adware_Lop_179
{
strings:
	$a0 = { de8f31e0744570d014078509c379fb6065549fa43b1da7cda768fcf4a46cd447bcad7ccc04bc1f30e91fce6b89b26517c529f4999ec1a529e2b5e032 }


condition:
	$a0
}