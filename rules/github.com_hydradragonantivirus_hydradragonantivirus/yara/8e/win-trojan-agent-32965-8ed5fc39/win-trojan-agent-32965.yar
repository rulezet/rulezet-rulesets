rule Win_Trojan_Agent_32965
{
strings:
	$a0 = { a071a2ecd61a351df2abc7eedacd4c8409cb3d532e278ec2367876e7d58f13c2d69efe16c3b1910ec75ffde36a7559d04bfa4877f414d60380075a2b48f7cf958767ad6962d1597fdda188397e3c }


condition:
	$a0
}