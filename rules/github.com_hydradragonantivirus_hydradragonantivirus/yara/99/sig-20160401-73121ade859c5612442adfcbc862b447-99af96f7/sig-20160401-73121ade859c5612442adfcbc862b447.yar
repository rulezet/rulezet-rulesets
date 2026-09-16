rule sig_20160401_73121ade859c5612442adfcbc862b447 {
  meta:
    description = "datamaliciousorder - file 20160401_73121ade859c5612442adfcbc862b447.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fd438f3767fe62c3a0e3768e08643fff722a7428a3cdd26d9de13e497905262"

  strings:
    $s1  = "CDDSSFF = String[(\"abortion\",\"danish\",\"striking\",\"f\")+(\"archer\",\"engender\",\"charming\",\"ro\")+\"mC\"+\"ha\"+\"rC\"" ascii
    $s2  = "EkOmUuQb = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && " ascii
    $s3  = "EkOmUuQb = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && " ascii
    $s4  = "LfowrzqdiiF = \" data = elem.getAttribute( name );\";" fullword ascii
    $s5  = "var DefUdd = sphinx + 5;" fullword ascii
    $s6  = "CDDSSFF = String[(\"abortion\",\"danish\",\"striking\",\"f\")+(\"archer\",\"engender\",\"charming\",\"ro\")+\"mC\"+\"ha\"+\"rC\"" ascii
    $s7  = "cies\",\"automation\",\"autumn\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s8  = "AuwIUF = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data ) " ascii
    $s9  = "synthesis = ((\"divorced\", \"opponent\", \"doorstep\", \"charger\", \"pKbfOOcRX\") + \"fSHxIEor\").inner(0);" fullword ascii
    $s10 = "   EaOnixsDLE = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( (" ascii
    $s11 = "!id || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s12 = "Array.prototype.intersection = function(){" fullword ascii
    $s13 = "String.prototype.inner = function (discs) {" fullword ascii
    $s14 = "egyacRa = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s15 = "as a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s16 = "        WgxlrrLcMc = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s17 = "        yzKWoXMGgwG = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isE" ascii
    $s18 = "        yzKWoXMGgwG = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isE" ascii
    $s19 = "across the DOM-JS boundary isNode = elem.nodeType,\";" fullword ascii
    $s20 = " \\\"null\\\" ? null :\";" fullword ascii

  condition:
    uint16(0) == 0x6b45 and
    8 of them
}