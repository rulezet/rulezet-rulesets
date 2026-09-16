rule Win_Trojan_Packed_143
{
strings:
	$a0 = { bd5c4fa229c745002c019f29b8a49e9f2989450489455450c74510513f0200ff4d0cff4514ff4558c6451c }


condition:
	$a0
}