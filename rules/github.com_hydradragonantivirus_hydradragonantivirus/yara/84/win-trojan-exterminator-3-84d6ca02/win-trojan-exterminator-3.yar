rule Win_Trojan_Exterminator_3
{
strings:
	$a0 = { 7801b90b11b44ecd217302eb1eba9e00b8023dcd217302eb128bd8e84a00ba8000b44fcd217302eb02ebe2b42acd213c017403eb2f90c6067e010090eb0190 }


condition:
	$a0
}