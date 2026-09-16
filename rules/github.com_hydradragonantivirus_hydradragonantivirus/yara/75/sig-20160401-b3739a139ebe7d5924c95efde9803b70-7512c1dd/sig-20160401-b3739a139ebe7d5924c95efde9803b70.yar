rule sig_20160401_b3739a139ebe7d5924c95efde9803b70 {
  meta:
    description = "datamaliciousorder - file 20160401_b3739a139ebe7d5924c95efde9803b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e2a3b49e3e38167f919f6b0fe579afbd479fe099622ac652f6c4a153c58c74f"

  strings:
    $s1  = "unprotected = ((\"dally\", \"truncheon\", \"heater\", \"flicker\", \"pWLEwpP\") + \"OKeUAhH\").passing(0);" fullword ascii
    $s2  = "CDDSSFF = String[(\"boost\",\"novelty\",\"equation\",\"f\")+(\"living\",\"unveil\",\"fatigues\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+\"o" ascii
    $s3  = "CDDSSFF = String[(\"boost\",\"novelty\",\"equation\",\"f\")+(\"living\",\"unveil\",\"fatigues\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+\"o" ascii
    $s4  = "LGAxonHe = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && " ascii
    $s5  = "LGAxonHe = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && " ascii
    $s6  = "String.prototype.passing = function (miguel) {" fullword ascii
    $s7  = "onfusion\",\"hi\")+\"sh\"+\"um\"+\"el\"+(\"dearborn\",\"adverbs\",\"dialog\",\"grieving\",\"a.\")+(\"assuage\",\"healthful\",\"l" ascii
    $s8  = "RrtqOQuHE = \" data = elem.getAttribute( name );\";" fullword ascii
    $s9  = "poplar\",\"matrix\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s10 = "vUJbIsBfC = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data" ascii
    $s11 = " !id || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s12 = "cal\", \"nwHMpLdEi\") + \"AocYoqu\").passing(roseate) + ((\"selective\", \"jewelry\", \"contest\", \"mathematical\", \"advertise" ascii
    $s13 = "yWhFrG = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s14 = "var Kolldq =benignants + (\"breastwork\",\"accessories\",\"usual\",\"pauper\",\"e\") + ((\"leslie\", \"shoppers\", \"suppose\", " ascii
    $s15 = "   VbJuMucdSye = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( " ascii
    $s16 = "        seAdUajTt = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s17 = "a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s18 = "        LTlWxHli = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii
    $s19 = "        LTlWxHli = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii
    $s20 = "null\\\" ? null :\";" fullword ascii

  condition:
    uint16(0) == 0x474c and
    8 of them
}