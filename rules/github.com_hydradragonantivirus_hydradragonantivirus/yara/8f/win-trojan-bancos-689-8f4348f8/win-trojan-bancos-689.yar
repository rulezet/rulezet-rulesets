rule Win_Trojan_Bancos_689
{
strings:
	$a0 = { ff6315ec1bca563a39b8e1f9dd4f56cdbf9c8341004d415e64ec954831133c7e1ef455b576e459611e41e37b231961762ba7beb44f29be8ebe2e5c13a21e0ac54ba5cfcb7964b404ef9bc441 }


condition:
	$a0
}