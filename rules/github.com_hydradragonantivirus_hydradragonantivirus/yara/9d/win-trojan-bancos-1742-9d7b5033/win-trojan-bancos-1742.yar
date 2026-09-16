rule Win_Trojan_Bancos_1742
{
strings:
	$a0 = { d5b34e0893da6d50bbdf651a0946e2ebe1ba2b264553d15de170161e1393cc15d145d0830e08ab656c3297601cd77f7c4e963f208d8810cbff51d6c7d2ceaa9ae20a384c9a57 }


condition:
	$a0
}