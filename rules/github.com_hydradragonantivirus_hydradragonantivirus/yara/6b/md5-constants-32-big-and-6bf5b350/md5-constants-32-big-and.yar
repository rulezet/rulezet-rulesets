rule MD5_constants__32_big_AND_
{
strings:
	$a0 = { 67452301[0-20]10325477[0-20]67452302[0-20]10325476 }

condition:
	$a0
}