rule Win_Trojan_Mybot_5493
{
strings:
	$a0 = { 8506eea998d17630a28a5b9c99b92619771ed30a9cdb79eea5888ebe73d40f529744f158d76eb651dad3d7c669184c29fe55d1878d767f62c7eedcf7e7200aed9cbce0daa565 }


condition:
	$a0
}