rule sig_20160401_0d1dac7b52c0214e2e063785f05e1de1 {
  meta:
    description = "datamaliciousorder - file 20160401_0d1dac7b52c0214e2e063785f05e1de1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1a342d761548a37f6d5da3412240cead29ee5d512bc9ee6e73562ecaed3aa4f"

  strings:
    $s1  = "CDDSSFF = String[(\"feign\",\"either\",\"christie\",\"f\")+(\"raven\",\"topped\",\"tributary\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+\"od" ascii
    $s2  = "sRbeyfcuF = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s3  = "sRbeyfcuF = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s4  = "ksQABIfTtRP = \" data = elem.getAttribute( name );\";" fullword ascii
    $s5  = "y\",\"specify\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s6  = "shTvRNDJq = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data" ascii
    $s7  = "Array.prototype.tropic = function(){" fullword ascii
    $s8  = "   XVskpHNX = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !" ascii
    $s9  = "d || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s10 = "infuse = ((\"fundamentals\", \"technique\", \"overdue\", \"passively\", \"pXAbDmfvRnm\") + \"JVhPeGI\").calabash(0);" fullword ascii
    $s11 = "dvDCFoXBG = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s12 = "    burman.agonised = burman.taurus[(\"c\"+\"hD\"+\"rA\"+(\"probity\",\"compute\",\"lengthen\",\"t\")).replace(\"D\", CDDSSFF)](" ascii
    $s13 = "s a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s14 = "    burman.agonised = burman.taurus[(\"c\"+\"hD\"+\"rA\"+(\"probity\",\"compute\",\"lengthen\",\"t\")).replace(\"D\", CDDSSFF)](" ascii
    $s15 = "        XVUQMrH = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s16 = "\\\"null\\\" ? null :\";" fullword ascii
    $s17 = "        FMvwyJAyQ = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmp" ascii
    $s18 = "        FMvwyJAyQ = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmp" ascii
    $s19 = "ect( obj[ name ] ) ) { continue; } if ( name !== \\\"toJSON\\\" ) { return false; } \";" fullword ascii
    $s20 = "var Kolldq =irwins + (\"heyday\",\"cocks\",\"exchange\",\"latitude\",\"e\") + ((\"there\", \"rheumatism\", \"indisputable\", \"s" ascii

  condition:
    uint16(0) == 0x5273 and
    8 of them
}