rule apt_CN_Tetris_JS_simple
{

	meta:
		author      = "@imp0rtp3"
		description = "Jetriz, Swid & Jeniva from Tetris framework signature"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		
	strings:
		$a1 = "c2lnbmFs" 		$a2 = "ZW50cmllcw==" 		$a3 = "aGVhcnRCZWF0cw==" 		$a4 = "ZmV0Y2g=" 		$a5 = "c3BsaWNl" 		$a6 = "TWl1aUJyb3dzZXI=" 		$a7 = "Zm9udA==" 		$a8 = "OS4w" 		$a9 = "Xi4qS29ucXVlcm9yXC8oW1xkLl0rKS4qJA==" 		$a10 = "dHJpbVJpZ2h0" 		$a11 = "UHJlc3Rv" 		$a12 = "Xi4qUWlob29Ccm93c2VyXC8oW1xkLl0rKS4qJA==" 		$a13 = "bWFyaw==" 		$a14 = "cHJvamVjdElk" 		$a15 = "IHJlcXVpcmVkIQ==" 
		$b1 = "var a0_0x"

	condition:
		$b1 at 0 or
		5 of ($a*)

}