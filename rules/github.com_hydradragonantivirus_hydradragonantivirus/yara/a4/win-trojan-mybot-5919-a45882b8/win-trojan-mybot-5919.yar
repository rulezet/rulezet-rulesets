rule Win_Trojan_Mybot_5919
{
strings:
	$a0 = { 6e000e04e451c9e9bd453acfc2c9c81fbf3444ea55f3f324c44502e1e739507276bbe47ca27f45dcf7f89f286149ae5fa46c5bb584c149 }


condition:
	$a0
}