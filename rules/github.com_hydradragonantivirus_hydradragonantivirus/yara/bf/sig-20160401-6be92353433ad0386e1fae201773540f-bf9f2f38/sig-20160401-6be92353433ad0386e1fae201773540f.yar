rule sig_20160401_6be92353433ad0386e1fae201773540f {
  meta:
    description = "datamaliciousorder - file 20160401_6be92353433ad0386e1fae201773540f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97f2da243fe8d142682c628bc8ec62d720284f90eb6b40287e62acdbf1b7c4f0"

  strings:
    $s1  = "CDDSSFF = String[(\"bulge\",\"grant\",\"sleeve\",\"f\")+(\"nominations\",\"deceitful\",\"suffolk\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+" ascii
    $s2  = "var Kolldq =budgets + (\"addicted\",\"produces\",\"agone\",\"tournament\",\"e\") + ((\"impersonation\", \"drivers\", \"looksmart" ascii
    $s3  = "CDDSSFF = String[(\"bulge\",\"grant\",\"sleeve\",\"f\")+(\"nominations\",\"deceitful\",\"suffolk\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+" ascii
    $s4  = "LyaSFKu = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && e" ascii
    $s5  = "LyaSFKu = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && e" ascii
    $s6  = "CXwCpRwjs = \" data = elem.getAttribute( name );\";" fullword ascii
    $s7  = "ermination\",\"concluded\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s8  = "var DefUdd = tonight + 5;" fullword ascii
    $s9  = "yhehcw = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data ) " ascii
    $s10 = "d || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s11 = "String.prototype.delineation = function (conventions) {" fullword ascii
    $s12 = "Array.prototype.smaller = function(){" fullword ascii
    $s13 = "   ueqksIXa = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !" ascii
    $s14 = "FNBSalqlK = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s15 = "\"purport\", \"nwHMpLdEi\") + \"AocYoqu\").delineation(unification) + ((\"connecticut\", \"differential\", \"almond\", \"elopeme" ascii
    $s16 = " DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s17 = "        LLfMNw = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s18 = "            LltrP[(annie).reverse().join(\"\")]((\"hindrance\",\"upbraid\",\"accountable\",\"G\") + numerouse + (\"oblation\",\"" ascii
    $s19 = "\\\"null\\\" ? null :\";" fullword ascii
    $s20 = "        qJlobU = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmptyO" ascii

  condition:
    uint16(0) == 0x794c and
    8 of them
}