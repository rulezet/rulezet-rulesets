rule Win_Spyware_Banker_2677
{
strings:
	$a0 = { 29710f4ff67d83f4bbd4a2859382285dda1915ad420835cdc060850bfca47d9da6149815f5c4cc1f8160d62db2444cf16e7705fe4a924799afdd }


condition:
	$a0
}