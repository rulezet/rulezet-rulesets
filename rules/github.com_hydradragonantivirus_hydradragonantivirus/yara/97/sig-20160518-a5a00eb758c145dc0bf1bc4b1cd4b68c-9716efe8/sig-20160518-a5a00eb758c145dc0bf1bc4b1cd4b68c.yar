rule sig_20160518_a5a00eb758c145dc0bf1bc4b1cd4b68c {
  meta:
    description = "datamaliciousorder - file 20160518_a5a00eb758c145dc0bf1bc4b1cd4b68c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da509883a17610e8a8eedddc6ba131bbbfe84f42bb3b10ccbb160afab3749ce7"

  strings:
    $s1  = "var modification = [obituaries, oasis,relationship,  \"\"+\".\"+(\"masonic\",\"permanent\",\"broadsword\",\"dedicated\",\"unwise" ascii
    $s2  = "\"namur\",\"expenses\",\"cr\")+(\"cheats\",\"hilarious\",\"militarism\",\"dynamite\",\"mixing\",\"spectral\",\"prickly\",\"modul" ascii
    $s3  = "        salaries[(piers + \"o\"+(\"spruce\",\"highways\",\"caribou\",\"outcomes\",\"beaker\",\"promised\",\"polyphonic\",\"comfo" ascii
    $s4  = "dummy(\"aHR0cDovLw==\".pastime4()+\"\\u0066\\u006F\\u006C\\u006C\\u0079\\u0066\\u006F\\u006F\\u0074\\u002E\"+\"\\u006F\\u0072\\u" ascii
    $s5  = "weasel = ((\"fathers\", \"profundity\", \"limitations\", \"embarkation\", \"EEJVQhnjhc\") + \"gmPDzGdz\").pastime2();" fullword ascii
    $s6  = "String.prototype.pastime = function () {" fullword ascii
    $s7  = "String.prototype.pastime4 = function() {" fullword ascii
    $s8  = "String.prototype.pastime2 = function () {" fullword ascii
    $s9  = "\",\"designing\",\"young\",\"olive\",\"script\",\"08\"), spire)] = 0;" fullword ascii
    $s10 = "var oasis =\"RXhwYW5collinskRW52aXcollinsJvbm1lbnRTdHJcollinspbmdz\".pastime4();" fullword ascii
    $s11 = "var afraid = new esthetic(enemies[1]);" fullword ascii
    $s12 = "function dummy(brittle, christening) {" fullword ascii
    $s13 = "shock = this;" fullword ascii
    $s14 = "var watched = 0;" fullword ascii
    $s15 = "contractor = contractor+ modification.shift();" fullword ascii
    $s16 = "spire = ((\"productivity\", \"upland\", \"abruptness\", \"canadian\", \"sSiLsIHjfCmV\") + \"qdkjIGfmD\").pastime2();" fullword ascii
    $s17 = "ttle, false);" fullword ascii
    $s18 = "var relationship =\"JVcollinsRFTVcollinsAl\".pastime4();" fullword ascii
    $s19 = "strangle = \"b3Blbg==\".pastime4();;" fullword ascii
    $s20 = "  septuagint = [];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}