rule Win_Trojan_Hupigon_493
{
strings:
	$a0 = { 9a876f1cb13fccef2165f141838fd95114f0dd37b1cc9f660778313e5f2f93d922faf07f75e4efbd80e1e497e0a459b0f923afee68ae3900fb9e306d22e56e213af395d029f82cfae9810cd9fcec }


condition:
	$a0
}