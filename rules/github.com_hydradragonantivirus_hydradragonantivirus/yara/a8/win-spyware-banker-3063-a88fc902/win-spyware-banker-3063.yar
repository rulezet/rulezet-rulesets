rule Win_Spyware_Banker_3063
{
strings:
	$a0 = { d5c20ad4011059daab9ed20c76580b425a7e52f3f608e836a2eb92cd53e915b1eba115258689bef933b6736ca551b75d9d53cfb64cc55babe8ec5d334b55 }


condition:
	$a0
}