rule Win_Trojan_Disnomia_1
{
strings:
	$a0 = { 1a6811cdf54097a914251fd1e55c55ec1415d9776757ec9ba075d97b9eb59d52155d1a59ad4d14de }


condition:
	$a0
}