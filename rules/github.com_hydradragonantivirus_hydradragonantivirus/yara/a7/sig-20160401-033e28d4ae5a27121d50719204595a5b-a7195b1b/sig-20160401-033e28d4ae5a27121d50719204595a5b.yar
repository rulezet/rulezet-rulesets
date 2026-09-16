rule sig_20160401_033e28d4ae5a27121d50719204595a5b {
  meta:
    description = "datamaliciousorder - file 20160401_033e28d4ae5a27121d50719204595a5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac2883a18a772f125af1b101e0615f2730b296fa3518fbfcd3e82719cc10d74d"

  strings:
    $s1  = "CDDSSFF = String[(\"sacramento\",\"essays\",\"sender\",\"f\")+(\"pubmed\",\"eclipse\",\"digits\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+\"" ascii
    $s2  = "CDDSSFF = String[(\"sacramento\",\"essays\",\"sender\",\"f\")+(\"pubmed\",\"eclipse\",\"digits\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+\"" ascii
    $s3  = "lmkceicSGic = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined " ascii
    $s4  = "ygrtjtk = \" data = elem.getAttribute( name );\";" fullword ascii
    $s5  = "cholera\", \"nwHMpLdEi\") + \"AocYoqu\").stockholm(enunciation) + ((\"tablet\", \"possibilities\", \"avalanche\", \"daughter\", " ascii
    $s6  = "lmkceicSGic = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined " ascii
    $s7  = "var Kolldq =tradespeoples + (\"cultures\",\"buying\",\"beginning\",\"thinking\",\"e\") + ((\"barrow\", \"ennui\", \"woodman\", " ascii
    $s8  = "var DefUdd = enter + 5;" fullword ascii
    $s9  = "e\",\"titled\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s10 = "deflection = ((\"artery\", \"staffing\", \"pedestal\", \"stability\", \"pwaCnSgbe\") + \"qRhdbw\").stockholm(0);" fullword ascii
    $s11 = "qpEIlQM = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data )" ascii
    $s12 = "KJqMHGFT = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s13 = "   UXWRSP = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !id" ascii
    $s14 = "String.prototype.stockholm = function (discrete) {" fullword ascii
    $s15 = "Array.prototype.scientist = function(){" fullword ascii
    $s16 = "|| !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s17 = "        WgpEtRTHP = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s18 = "        ufJlDXdGX = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmp" ascii
    $s19 = "        ufJlDXdGX = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmp" ascii
    $s20 = "    heRoKW = \" Only defining an ID for JS objects if its cache already exists allows the code to shortcut on the same path as a" ascii

  condition:
    uint16(0) == 0x6d6c and
    8 of them
}