rule anti_debug__CheckForSoftICEBP__8_byt_18_
{
strings:
	$a0 = { 561e0e1f8b76028b3689f025ff0000003ccc }

condition:
	$a0
}