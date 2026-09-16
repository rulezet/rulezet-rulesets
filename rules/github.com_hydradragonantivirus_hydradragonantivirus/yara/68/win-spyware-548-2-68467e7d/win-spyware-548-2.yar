rule Win_Spyware_548_2
{
strings:
	$a0 = { 08a0cfbaaccb8a140ef1ec9f33c025b3ec841c3048dee0cbd63980a673d0eb789e013a3b05ba0a90a78f6582a8e6a28e683a5ffb8916d76ae70a45eee173a80d8b46605ed8a2099895ccba31076b }


condition:
	$a0
}