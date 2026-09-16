rule sig_20160404_af21a7ae1d234acd58142979e6e88dac {
  meta:
    description = "datamaliciousorder - file 20160404_af21a7ae1d234acd58142979e6e88dac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31688d43f400cb00ca39c6ed7ed8418d49eca5f8af3b27432a5af8e8dd528da7"

  strings:
    $s1  = "hcXuoznEbP = \"} An object can be passed to jQuery.data instead of a key/value pair; this gets shallow copied over onto the exis" ascii
    $s2  = "hcXuoznEbP = \"} An object can be passed to jQuery.data instead of a key/value pair; this gets shallow copied over onto the exis" ascii
    $s3  = "var fusillade = [(\"going\",\"trash\",\"accusing\",\"contact\",\"Act\")+\"iveXOb\"+(\"fundamentally\",\"preliminary\",\"chisel\"" ascii
    $s4  = "JBjJTgqqK = \" jQuery data() is stored in a separate object inside the object\\\"s internal data cache in order to avoid key col" ascii
    $s5  = "morphine = ((\"beach\", \"state\", \"tyrannous\", \"transcend\", \"sHsQaVV\") + \"kReVGmKDM\").baking();" fullword ascii
    $s6  = "var apparatus1 = 7*2*7 + apparatus;" fullword ascii
    $s7  = "draughts = (\"n\"+(\"dryness\",\"health\",\"ep\") + String.fromCharCode(110+apparatus2)).split(\"\");" fullword ascii
    $s8  = "crystallization = ((\"seventytwo\", \"verse\", \"bountiful\", \"suggesting\", \"pnAyfOjwUMHu\") + \"BLzMwzXBRQ\").baking();" fullword ascii
    $s9  = "var pestle = fusillade.pop().split(\"" fullword ascii
    $s10 = "var compress = new throughout(pestle[1]);" fullword ascii
    $s11 = "String.prototype.brisbane = function () {" fullword ascii
    $s12 = "var deciduous = compress[fusillade.shift()](fusillade.shift());" fullword ascii
    $s13 = "ions between internal data and user-defined data. if ( !pvt ) { if ( !thisCache.data ) { thisCache.data = {}; \";" fullword ascii
    $s14 = "String.prototype.baking = function () {" fullword ascii
    $s15 = "morphine + \"e\"+oreilly.toUpperCase()+\"o\"+(\"chancery\",\"neigh\",\"properties\",\"dy\")]);" fullword ascii
    $s16 = ", integer, false);" fullword ascii
    $s17 = "f ( typeof name === \\\"string\\\" ) {\";" fullword ascii
    $s18 = "oreilly = String[(\"scythe\",\"precision\",\"thrive\",\"nether\",\"f\")+(\"butchers\",\"igneous\",\"avenue\",\"ro\")+\"mC\"+\"ha" ascii
    $s19 = "d ], name ); } else { cache[ id ].data = jQuery.extend( cache[ id ].data, name ); } \";" fullword ascii
    $s20 = "var fusillade = [(\"going\",\"trash\",\"accusing\",\"contact\",\"Act\")+\"iveXOb\"+(\"fundamentally\",\"preliminary\",\"chisel\"" ascii

  condition:
    uint16(0) == 0x6368 and
    8 of them
}