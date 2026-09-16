rule Win_Trojan_Banbra_151
{
strings:
	$a0 = { 89f3baede7d3c0c0a84136759eae03852f9e6bda59794d02a76c0527bba0706930fc8946d93037202a6758787248369eac6c339989 }


condition:
	$a0
}