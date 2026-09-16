rule Win_Spyware_Banker_2745
{
strings:
	$a0 = { cd5876a34f5ee6089c4ee5d6632e4d4f424d2c66cbfb68e5ec58eebcd129f2a30e3fd8216684506049a1e7bd2e40eef91cb4fbeaa9e34a03acc70cd0904af361677b79773bb7d84da179efb1e6d7 }


condition:
	$a0
}