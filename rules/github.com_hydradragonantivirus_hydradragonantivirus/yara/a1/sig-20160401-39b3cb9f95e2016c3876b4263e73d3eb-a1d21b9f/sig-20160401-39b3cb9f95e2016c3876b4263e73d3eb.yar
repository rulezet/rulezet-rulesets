rule sig_20160401_39b3cb9f95e2016c3876b4263e73d3eb {
  meta:
    description = "datamaliciousorder - file 20160401_39b3cb9f95e2016c3876b4263e73d3eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e953e9d0e36a487af94cdf11b5857fb387fa06f1c762befc712e798270efa4b"

  strings:
    $s1  = "CDDSSFF = String[(\"soldier\",\"grannie\",\"arbor\",\"f\")+(\"distributed\",\"completing\",\"video\",\"ro\")+\"mC\"+\"ha\"+\"rC" ascii
    $s2  = "oJuuvc = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && el" ascii
    $s3  = "oJuuvc = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && el" ascii
    $s4  = "CDDSSFF = String[(\"soldier\",\"grannie\",\"arbor\",\"f\")+(\"distributed\",\"completing\",\"video\",\"ro\")+\"mC\"+\"ha\"+\"rC" ascii
    $s5  = "bRxyPzn = \" data = elem.getAttribute( name );\";" fullword ascii
    $s6  = "bbreviated\", \"nwHMpLdEi\") + \"AocYoqu\").evaporate(favor) + ((\"closely\", \"absorbs\", \"exhaust\", \"genes\", \"subside\", " ascii
    $s7  = "GDndLokosX = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( dat" ascii
    $s8  = "var DefUdd = vivacious + 5;" fullword ascii
    $s9  = "\",\"photographic\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s10 = "|| !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s11 = "Array.prototype.senegal = function(){" fullword ascii
    $s12 = "zAcTKjknIM = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s13 = "   ysPJcA = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !id" ascii
    $s14 = "        oxmyIMOLkF = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s15 = " DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s16 = "        yYeXtHs = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpty" ascii
    $s17 = "        yYeXtHs = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpty" ascii
    $s18 = "IDNitghxIn = \" if ( typeof data === \\\"string\\\" ) { try { data = data === \\\"true\\\" ? true : data === \\\"false\\\" ? fal" ascii
    $s19 = "    NjAjvJU = \" Only defining an ID for JS objects if its cache already exists allows the code to shortcut on the same path as " ascii
    $s20 = "cross the DOM-JS boundary isNode = elem.nodeType,\";" fullword ascii

  condition:
    uint16(0) == 0x4a6f and
    8 of them
}