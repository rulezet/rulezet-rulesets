rule Win_Spyware_Banker_1463
{
strings:
	$a0 = { a6ecb66cb58ac1bb3060473bbb52c7c0f52d90de25863fc48ffe5d275551df6ff150769fbb5d2935db6337b140d79d0a46388829076be4cdb6f5a0a57e5a990ee8e39874 }


condition:
	$a0
}