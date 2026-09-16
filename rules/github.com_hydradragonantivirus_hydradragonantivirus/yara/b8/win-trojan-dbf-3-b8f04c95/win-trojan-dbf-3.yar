rule Win_Trojan_DBF_3
{
strings:
	$a0 = { 01bedc032e80350c474e71f880c409090c82d4add208314156790ee724b5100cb2d208b30c0d87d386082284094a }


condition:
	$a0
}