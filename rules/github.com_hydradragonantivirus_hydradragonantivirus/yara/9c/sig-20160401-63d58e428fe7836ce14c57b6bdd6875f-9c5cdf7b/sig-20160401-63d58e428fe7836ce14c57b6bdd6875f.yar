rule sig_20160401_63d58e428fe7836ce14c57b6bdd6875f {
  meta:
    description = "datamaliciousorder - file 20160401_63d58e428fe7836ce14c57b6bdd6875f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85390feabf4bfb3bdbe6c470492ce7c55d2c7853a765bd40fb6b3e940a0d220e"

  strings:
    $s1  = "CDDSSFF = String[(\"extra\",\"tennis\",\"reilly\",\"f\")+(\"motion\",\"tardiness\",\"complicity\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+" ascii
    $s2  = "\"democrat\", \"nwHMpLdEi\") + \"AocYoqu\").disrespectful(symphony) + ((\"errol\", \"apply\", \"bleaching\", \"gentle\", \"firms" ascii
    $s3  = "var Kolldq =aloofnesss + (\"optics\",\"bulgarian\",\"versatile\",\"solved\",\"e\") + ((\"expression\", \"unlock\", \"ravenously" ascii
    $s4  = "CDDSSFF = String[(\"extra\",\"tennis\",\"reilly\",\"f\")+(\"motion\",\"tardiness\",\"complicity\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+" ascii
    $s5  = "gEyqYvuoV = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s6  = "gEyqYvuoV = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s7  = "SPyEIze = \" if ( typeof data === \\\"string\\\" ) { try { data = data === \\\"true\\\" ? true : data === \\\"false\\\" ? false " ascii
    $s8  = "SPyEIze = \" if ( typeof data === \\\"string\\\" ) { try { data = data === \\\"true\\\" ? true : data === \\\"false\\\" ? false " ascii
    $s9  = "HTBlbLuuRSn = \" data = elem.getAttribute( name );\";" fullword ascii
    $s10 = "        var extreme = BSfuntnX + \"/\" + flower + YzkiL.shift();" fullword ascii
    $s11 = "var DefUdd = ethereal + 5;" fullword ascii
    $s12 = "CkGaMT = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data ) " ascii
    $s13 = "\",\"medicine\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s14 = "untidy = ((\"crescent\", \"spurt\", \"rudder\", \"handmade\", \"pCIFxGYwrEqQ\") + \"NMpeBNm\").disrespectful(0);" fullword ascii
    $s15 = " !id || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s16 = "String.prototype.disrespectful = function (bruce) {" fullword ascii
    $s17 = "Array.prototype.ordination = function(){" fullword ascii
    $s18 = "coOrrzPl = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s19 = "   yUwefNIpTOv = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( " ascii
    $s20 = " a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii

  condition:
    uint16(0) == 0x4567 and
    8 of them
}