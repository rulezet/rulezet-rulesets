rule Win_Trojan_V_5
{
strings:
	$a0 = { 75e3e96c029090b80104b90100ba0000cd137311b80104cd13730ab80104cd137303e99d01 }


condition:
	$a0
}