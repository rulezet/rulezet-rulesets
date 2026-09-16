rule Win_Trojan__1055_0005_000_1
{
strings:
	$a0 = { 023dba9e00cd2193b91103b440ba0001cd21b43ecd21ff060c04833e0c04057d03e8d4ffb43b }


condition:
	$a0
}