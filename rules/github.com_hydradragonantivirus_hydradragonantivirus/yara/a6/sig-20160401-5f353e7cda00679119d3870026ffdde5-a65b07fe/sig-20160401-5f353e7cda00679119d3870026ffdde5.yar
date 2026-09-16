rule sig_20160401_5f353e7cda00679119d3870026ffdde5 {
  meta:
    description = "datamaliciousorder - file 20160401_5f353e7cda00679119d3870026ffdde5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5abad08a3176be85ec66c0f420a484a24347afd5732070f7596e21184994e928"

  strings:
    $s1  = "QGUDbzhYnS = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &" ascii
    $s2  = "feguEmVTSk = \" data = elem.getAttribute( name );\";" fullword ascii
    $s3  = "cinnamon = ((\"fraud\", \"affordable\", \"subjectmatter\", \"contiguity\", \"pwnhRwTK\") + \"IdFAuReUDrb\").episodes(0);" fullword ascii
    $s4  = "QGUDbzhYnS = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &" ascii
    $s5  = " winner -1);" fullword ascii
    $s6  = "        xsefdhsr[(cinnamon + (\"abhor\",\"lafayette\",\"o\")+\"Di\"+(\"postage\",\"belongings\",\"ti\")+\"on\").replace(\"D\", t" ascii
    $s7  = "var Kolldq =toothlesss + (\"pressing\",\"adverbs\",\"pakistan\",\"newfoundland\",\"e\") + ((\"snowball\", \"lenient\", \"rubber" ascii
    $s8  = "var DefUdd = winner + 5;" fullword ascii
    $s9  = "CDDSSFF = String[(\"consumes\",\"symmetry\",\"examples\",\"f\")+(\"incandescent\",\"hansen\",\"wednesday\",\"ro\")+\"mC\"+\"ha\"" ascii
    $s10 = "RyxLow = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data ) " ascii
    $s11 = "elibacy\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s12 = ", \"multiple\", \"nwHMpLdEi\") + \"AocYoqu\").episodes(desist) + ((\"endowment\", \"alternatively\", \"benign\", \"outsider\", " ascii
    $s13 = " || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s14 = "String.prototype.episodes = function (rooms) {" fullword ascii
    $s15 = "Array.prototype.constrain = function(){" fullword ascii
    $s16 = "fDiioCuCjP = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s17 = "   MijWsFp = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !i" ascii
    $s18 = " DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s19 = "        ppMQOwVi = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s20 = "        LoYgJHPUjt = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEm" ascii

  condition:
    uint16(0) == 0x4751 and
    8 of them
}