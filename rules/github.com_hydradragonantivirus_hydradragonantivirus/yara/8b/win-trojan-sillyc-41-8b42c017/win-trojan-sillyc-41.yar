rule Win_Trojan_SillyC_41
{
strings:
	$a0 = { 030089868e012d020089860601b4408d960501b98c00cd21b800429933c9cd21b4408d968d01b1 }


condition:
	$a0
}