rule Win_Trojan_Hupigon_678
{
strings:
	$a0 = { 35a79eb9bfdbe3ce3a4b82d5fdf00160b968a30630ec6042ce41dcdcf6a546aaded211c0939cc0f43731fccf901125b8c84c3cc2cac6d5b6259d8e16a81b95e71d }


condition:
	$a0
}