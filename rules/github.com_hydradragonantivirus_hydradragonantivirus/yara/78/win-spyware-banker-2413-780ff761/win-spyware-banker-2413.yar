rule Win_Spyware_Banker_2413
{
strings:
	$a0 = { 264d6df6b5d31bbed58c4b0ffbdca6c62c44f83f0f3f437fb5de35af18dba2a40e9a80d4cbb99955865c5aba1d477036e46dc42e84b0e3acabe88977b73e8155361e6807b38d35b26603 }


condition:
	$a0
}