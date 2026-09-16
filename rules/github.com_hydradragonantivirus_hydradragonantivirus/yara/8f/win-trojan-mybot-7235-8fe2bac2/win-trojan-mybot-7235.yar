rule Win_Trojan_Mybot_7235
{
strings:
	$a0 = { dce727c43bdeac8a6f26900efe5948d3019cddd747c14a2ad98e7f93e8197651c06273b709762da194fe10d30b9ac46bdd0991a31c4a1031b0bdeaf333e4934e1144556ffe7ab30ef99cfdd783f9 }


condition:
	$a0
}