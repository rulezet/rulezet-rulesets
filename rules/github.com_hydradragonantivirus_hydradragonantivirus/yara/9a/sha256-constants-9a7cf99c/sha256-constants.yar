rule SHA256_Constants {
	meta:
		author = "Andrew Williams (@recvfrom)"
		description = "Look for SHA256 constants"
		date = "2020-10"
		version = "0.1"
	strings:
        $c_le_1 = { 6A09E667 }
        $c_le_2 = { BB67AE85 }
        $c_le_3 = { 3C6EF372 }
        $c_le_4 = { A54FF53A }
        $c_le_5 = { 510E527F }
        $c_le_6 = { 9B05688C }
        $c_le_7 = { 1F83D9AB }
        $c_le_8 = { 5BE0CD19 }
        $c_be_1 = { 67E6096A }
        $c_be_2 = { 85AE67BB }
        $c_be_3 = { 72F36E3C }
        $c_be_4 = { 3AF54FA5 }
        $c_be_5 = { 7F520E51 }
        $c_be_6 = { 8C68059B }
        $c_be_7 = { ABD9831F }
        $c_be_8 = { 19CDE05B }
	condition:
		5 of ($c_be_*) or 5 of ($c_le_*)
}