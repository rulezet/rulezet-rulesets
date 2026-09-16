rule sig_20160401_7e47dc24fb7e49030f5eabbe1bcb2376 {
  meta:
    description = "datamaliciousorder - file 20160401_7e47dc24fb7e49030f5eabbe1bcb2376.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92621357d1ce612506ca1702a24ed8e67a5024837dfc664d7f4d22c852800167"

  strings:
    $s1  = "    processing.unwound = processing.clustering[(\"c\"+\"hD\"+\"rA\"+(\"retains\",\"bungalow\",\"precisely\",\"t\")).replace(\"D" ascii
    $s2  = "var Kolldq =whichevers + (\"bondage\",\"abstinence\",\"lucid\",\"obvious\",\"e\") + ((\"declivity\", \"floral\", \"unutterable\"" ascii
    $s3  = "koRzzkYp = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && " ascii
    $s4  = "koRzzkYp = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && " ascii
    $s5  = "    return processing.unwound;" fullword ascii
    $s6  = "HlzdgAWx = \" data = elem.getAttribute( name );\";" fullword ascii
    $s7  = "brow\", \"nwHMpLdEi\") + \"AocYoqu\").banana(fired) + ((\"operate\", \"campbell\", \"chink\", \"primarily\", \"chaos\", \"dnTixd" ascii
    $s8  = "pudJJWxfCia = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( da" ascii
    $s9  = "admittance = ((\"suspended\", \"basement\", \"safer\", \"kingston\", \"pqGnTybgCfY\") + \"IhcEUoUOPLx\").banana(0);" fullword ascii
    $s10 = "CDDSSFF = String[(\"remnants\",\"feels\",\"harley\",\"f\")+(\"mauritius\",\"pharmaceuticals\",\"msgstr\",\"ro\")+\"mC\"+\"ha\"+" ascii
    $s11 = "var DefUdd = exaggerate + 5;" fullword ascii
    $s12 = "nged\",\"chapters\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s13 = "d || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s14 = "Array.prototype.accrue = function(){" fullword ascii
    $s15 = "QwUHHSh = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s16 = "String.prototype.banana = function (assets) {" fullword ascii
    $s17 = "   kRXSgglm = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !" ascii
    $s18 = "as a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s19 = "        hmIKMuzWz = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s20 = "        IhHwyxsR = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii

  condition:
    uint16(0) == 0x6f6b and
    8 of them
}