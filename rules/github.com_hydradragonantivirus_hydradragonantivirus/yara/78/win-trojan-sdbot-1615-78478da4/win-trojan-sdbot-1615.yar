rule Win_Trojan_SdBot_1615
{
strings:
	$a0 = { 915f5f0b80ebd1b4907b525c20696e41edd98700adbf4a2c0f69260dd1477d759fd0f369cfcc4a98390e5f6ddedc6b0760b8562e05341b0aef0127bf2250d934 }


condition:
	$a0
}