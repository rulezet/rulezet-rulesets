rule sig_20160518_058cd404bc63f6fb40c415b2ad823c6e {
  meta:
    description = "datamaliciousorder - file 20160518_058cd404bc63f6fb40c415b2ad823c6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fc499601056dad4028bcf0270051a73f9861c59ff7e87da14768b9af5432bad"

  strings:
    $s1  = "var aircraft = [darius, headquarters,sustenance,  \"\"+\".\"+(\"fatality\",\"uniform\",\"sarcophagus\",\"defensive\",\"reactiona" ascii
    $s2  = "unbalanced = unbalanced+ aircraft.shift();" fullword ascii
    $s3  = "var rational = aircraft.pop().split(\">\");" fullword ascii
    $s4  = "        luxury[(prohibit + \"o\"+(\"valuable\",\"susan\",\"ultimatum\",\"inlaid\",\"investigate\",\"circuitous\",\"absolution\"," ascii
    $s5  = "var concupiscence=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sixtysix4())&&tributary[\"c3RhdHVz\".sixtysix4()] +\"\"==\"MjA" ascii
    $s6  = "        var luxury = new congratulation(((\"idiosyncrasy\",\"docile\",\"addressed\",\"criticized\",\"lazarus\",\"clubs\",\"urgen" ascii
    $s7  = "var concupiscence=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sixtysix4())&&tributary[\"c3RhdHVz\".sixtysix4()] +\"\"==\"MjA" ascii
    $s8  = "ratios[aircraft.shift()](unbalanced, devastating, true);" fullword ascii
    $s9  = "var porpoise = ratios[aircraft.shift()](aircraft.shift());" fullword ascii
    $s10 = "var congratulation = this[aircraft.shift()];" fullword ascii
    $s11 = "var headquarters =\"RXhwYW5multiplekRW52aXmultipleJvbm1lbnRTdHJmultiplepbmdz\".sixtysix4();" fullword ascii
    $s12 = "var aircraft = [darius, headquarters,sustenance,  \"\"+\".\"+(\"fatality\",\"uniform\",\"sarcophagus\",\"defensive\",\"reactiona" ascii
    $s13 = "prohibit = ((\"laboratories\", \"obsequious\", \"allied\", \"tradesman\", \"pAlmiTa\") + \"aFABvMs\").sixtysix2();" fullword ascii
    $s14 = "gross = ((\"dunno\", \"zambia\", \"foundry\", \"sanctified\", \"syPHKEigQfC\") + \"LsYcrvmj\").sixtysix2();" fullword ascii
    $s15 = "weasel = ((\"conjuring\", \"umbrellas\", \"greene\", \"emacs\", \"EUuugEvoU\") + \"CjfiCv\").sixtysix2();" fullword ascii
    $s16 = "        luxury[(prohibit + \"o\"+(\"valuable\",\"susan\",\"ultimatum\",\"inlaid\",\"investigate\",\"circuitous\",\"absolution\"," ascii
    $s17 = "String.prototype.sixtysix = function () {" fullword ascii
    $s18 = "String.prototype.sixtysix4 = function() {" fullword ascii
    $s19 = "String.prototype.sixtysix2 = function () {" fullword ascii
    $s20 = "            tributary[brawny]((\"ordinary\",\"square\",\"G\" + weasel) + (\"researchers\",\"inadvertently\",\"unauthorized\",\"g" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}