rule Win_Trojan_NYB_3
{
strings:
	$a0 = { 8bd833c932f6414007c38b46108b5e0e8b4e0c8b560a8e4608c341b80102cd1380f280e964 }


condition:
	$a0
}