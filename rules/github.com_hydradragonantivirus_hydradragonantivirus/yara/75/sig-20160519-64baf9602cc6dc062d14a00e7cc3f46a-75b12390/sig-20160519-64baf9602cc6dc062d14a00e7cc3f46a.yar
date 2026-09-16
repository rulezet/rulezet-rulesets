rule sig_20160519_64baf9602cc6dc062d14a00e7cc3f46a {
  meta:
    description = "datamaliciousorder - file 20160519_64baf9602cc6dc062d14a00e7cc3f46a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2320b02a0ff31e1578030027eb1e6667086cdc6fc11d176009578832606e79c"

  strings:
    $s1  = "        unpretending[(unload + \"o\"+(\"corvette\",\"rebuild\",\"occupied\",\"framework\",\"rebuff\",\"errol\",\"wellington\",\"" ascii
    $s2  = "var adultery = [understanding, cakes,christie,  \"\"+\".\"+(\"taurus\",\"university\",\"crossbow\",\"therapy\",\"kodak\",\"octob" ascii
    $s3  = "unload = ((\"prepaid\", \"investigation\", \"agencies\", \"cologne\", \"pXRnbyRl\") + \"kdeiyfU\").chicks2();" fullword ascii
    $s4  = "\"indeed\",\"adapt\",\"montreal\",\"conducted\",\"accuser\",\"08\"), heterogeneous)] = 0;" fullword ascii
    $s5  = "String.prototype.chicks4 = function() {" fullword ascii
    $s6  = "String.prototype.chicks = function () {" fullword ascii
    $s7  = "String.prototype.chicks2 = function () {" fullword ascii
    $s8  = "        unpretending[(unload + \"o\"+(\"corvette\",\"rebuild\",\"occupied\",\"framework\",\"rebuff\",\"errol\",\"wellington\",\"" ascii
    $s9  = "heterogeneous = ((\"glacial\", \"facial\", \"parenting\", \"outdo\", \"erica\", \"legion\", \"sxsxBnrkwzv\") + \"MLwFuuN\").chic" ascii
    $s10 = "var articulation = 3-2;  " fullword ascii
    $s11 = "function ludlow(elderly, launches) {" fullword ascii
    $s12 = "weasel = ((\"disfigure\", \"intrepid\", \"abated\", \"swims\", \"EBQPYedI\") + \"FGPBcAyxNwI\").chicks2();" fullword ascii
    $s13 = "clearly = \"_F2_\";" fullword ascii
    $s14 = "var slightly = 0;" fullword ascii
    $s15 = "for (var i in demolished){effervescence = effervescence.replace(i, demolished[i]);}" fullword ascii
    $s16 = "var heterogeneous = new convalescent(mapped[1]);" fullword ascii
    $s17 = "var lives = new convalescent(mapped[0]);" fullword ascii
    $s18 = "var understanding = \"QWwelledN0aXZwelledlWE9iawelledmVjdA=welled=\".chicks4();" fullword ascii
    $s19 = "effervescence = this;" fullword ascii
    $s20 = "  chapel = [];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}