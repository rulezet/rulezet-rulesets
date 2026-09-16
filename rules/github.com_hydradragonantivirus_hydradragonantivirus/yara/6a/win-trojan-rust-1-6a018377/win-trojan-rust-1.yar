rule Win_Trojan_Rust_1
{
strings:
	$a0 = { da8ec2be6d018bfeb9b502e8b5fa5a071fc3b003cf }


condition:
	$a0
}