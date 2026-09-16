rule Win_Trojan_Alurewo_1
{
strings:
	$a0 = { 682ccb4000c33a0e40721b002ff7b3977924c551b3b3c508cb9f692ec5ff51ffcb792e909497b379b3df362ec5b3df089736df36699fff2ec55c51972e24df90 }


condition:
	$a0
}