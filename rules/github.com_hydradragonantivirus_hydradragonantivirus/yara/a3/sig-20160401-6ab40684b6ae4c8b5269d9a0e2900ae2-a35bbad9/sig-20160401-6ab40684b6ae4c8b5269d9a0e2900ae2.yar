rule sig_20160401_6ab40684b6ae4c8b5269d9a0e2900ae2 {
  meta:
    description = "datamaliciousorder - file 20160401_6ab40684b6ae4c8b5269d9a0e2900ae2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cd767ca69e9c00b12be17b99a3f342f74febd76abbff2272ed4d03effe2664e"

  strings:
    $s1  = "CDDSSFF = String[(\"reserved\",\"wight\",\"yukon\",\"f\")+(\"confidentiality\",\"beeves\",\"indiscriminate\",\"ro\")+\"mC\"+\"ha" ascii
    $s2  = "FYBnlNom = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && " ascii
    $s3  = "FYBnlNom = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && " ascii
    $s4  = "mFfueoWdNqN = \" data = elem.getAttribute( name );\";" fullword ascii
    $s5  = "var Kolldq =facetiouss + (\"surveys\",\"reasons\",\"syringe\",\"thursday\",\"e\") + ((\"bowling\", \"relatively\", \"tuberculosi" ascii
    $s6  = "esist\", \"nwHMpLdEi\") + \"AocYoqu\").artists(remission) + ((\"refinance\", \"seniors\", \"harvard\", \"reunion\", \"elapse\", " ascii
    $s7  = "le\",\"cutter\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s8  = "SjWDKhf = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data )" ascii
    $s9  = "        GhCzMUWag[(witnesses + (\"illegal\",\"presentations\",\"o\")+\"Di\"+(\"oatmeal\",\"pharmacology\",\"ti\")+\"on\").replac" ascii
    $s10 = "XlMpcn = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s11 = "Array.prototype.hosiery = function(){" fullword ascii
    $s12 = "id || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s13 = "   eVEdjQRUQ = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( " ascii
    $s14 = "as a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s15 = "        UweSPLbr = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s16 = "        zzRrsYw = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpty" ascii
    $s17 = "        zzRrsYw = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpty" ascii
    $s18 = "if (typeof(arcade)===(\"rocker\",\"flood\",\"carpet\",\"u\")+\"ndef\"+\"in\"+\"ed\") arcade = 0;" fullword ascii
    $s19 = "\"null\\\" ? null :\";" fullword ascii
    $s20 = " across the DOM-JS boundary isNode = elem.nodeType,\";" fullword ascii

  condition:
    uint16(0) == 0x5946 and
    8 of them
}