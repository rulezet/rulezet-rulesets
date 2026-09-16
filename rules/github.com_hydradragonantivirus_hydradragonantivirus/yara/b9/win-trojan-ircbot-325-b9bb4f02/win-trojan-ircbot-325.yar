rule Win_Trojan_IRCBot_325
{
strings:
	$a0 = { 54dcadaddb0f44aeaf46bddb77455858f2a97345587784068ac3fdfdfdfd44568a63fdfdfdfda4e11c50f62ea9adad3737b48456b9438da9adad93e7eeadb947ff95adadfd44a6afe7462fb943e895ad }


condition:
	$a0
}