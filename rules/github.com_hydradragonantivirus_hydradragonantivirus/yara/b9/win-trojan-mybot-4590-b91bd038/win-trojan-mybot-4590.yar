rule Win_Trojan_Mybot_4590
{
strings:
	$a0 = { 4edd028665235499147250dc8e6331ae2205fe53796e41636b2aab32550bb440e18388a8ebad6e50792d056cd33f504d54 }


condition:
	$a0
}