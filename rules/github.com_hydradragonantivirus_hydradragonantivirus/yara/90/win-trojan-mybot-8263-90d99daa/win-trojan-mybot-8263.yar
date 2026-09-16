rule Win_Trojan_Mybot_8263
{
strings:
	$a0 = { 1c5696221b521ed7bdea1ab5cf64e134008c46021c22b971a9fbb5bb6b29a6ae7a4f3526e6c38f6104e17c0aec976dc58c65287b000824768db75f26daec1a5244eacdc53d55 }


condition:
	$a0
}