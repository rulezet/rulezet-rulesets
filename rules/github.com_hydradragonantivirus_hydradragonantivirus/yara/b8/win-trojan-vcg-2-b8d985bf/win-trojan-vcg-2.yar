rule Win_Trojan_VCG_2
{
strings:
	$a0 = { b302e8a309b06de942013c6e751050e83301b80040b300e88e0958e92e013c6f7503e966f9 }


condition:
	$a0
}