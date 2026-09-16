rule Win_Trojan_Voronezh_8
{
strings:
	$a0 = { 1f50e800005b81eb080153b4abcd213d55557503e9d0008cc02d01008e }


condition:
	$a0
}