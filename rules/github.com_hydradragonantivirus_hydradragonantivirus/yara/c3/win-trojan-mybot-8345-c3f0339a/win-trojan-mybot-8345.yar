rule Win_Trojan_Mybot_8345
{
strings:
	$a0 = { 83d8f73cd66ddb1a464caafb61dd1fc81c8196460f3d7f148d5dd37fab5ebee1f1b07adfc21929c80d6fde2db10b55449aae9bedbec92c86661ff844759547e9ec218f2b88c543eb837e213ab9d28efe }


condition:
	$a0
}