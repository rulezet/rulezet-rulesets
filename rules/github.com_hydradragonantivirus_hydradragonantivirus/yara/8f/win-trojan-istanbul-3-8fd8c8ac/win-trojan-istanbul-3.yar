rule Win_Trojan_Istanbul_3
{
strings:
	$a0 = { 4bcd213d34347457e8a90274522ea12f0406488ec026 }


condition:
	$a0
}