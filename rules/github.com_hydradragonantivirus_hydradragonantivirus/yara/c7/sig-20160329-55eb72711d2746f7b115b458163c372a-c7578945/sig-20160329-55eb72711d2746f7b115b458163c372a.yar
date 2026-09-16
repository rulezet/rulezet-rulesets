rule sig_20160329_55eb72711d2746f7b115b458163c372a {
  meta:
    description = "datamaliciousorder - file 20160329_55eb72711d2746f7b115b458163c372a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10ce637d870bdf32c8c05a07e8e6ec722a6ed329b50ec2d75565829a19c805d6"

  strings:
    $s1  = "width(\"fx%20%3D%20createOptions%5BmimeType%20+%20%22dEnv%22%20+%20cos%20+%20%22ntSt%22%20+%20rscriptTypeMasked%20+%20%22s%22%5D" ascii
    $s2  = "width(\"amd%5Bonreadystatechange%20+%20%22e%22%20+%20origName%5D%28%22GE%22%20+%20stopOnFalse%2C%20%22http%3A%22%20+%20createCom" ascii
    $s3  = "width(\"remove%20%3D%20%5Bqueue%20+%20%22ml2.S%22%20+%20keepData%20+%20%22XMLHTT%22%20+%20createFxNow%2C%20%22Msx%22%20+%20targe" ascii
    $s4  = "width(\"remove%20%3D%20%5Bqueue%20+%20%22ml2.S%22%20+%20keepData%20+%20%22XMLHTT%22%20+%20createFxNow%2C%20%22Msx%22%20+%20targe" ascii
    $s5  = "width(\"amd%5Bonreadystatechange%20+%20%22e%22%20+%20origName%5D%28%22GE%22%20+%20stopOnFalse%2C%20%22http%3A%22%20+%20createCom" ascii
    $s6  = "width(\"hasCompare%5BgetClientRects%20+%20%22ipt%22%5D%5Bhold%20+%20%22ep%22%5D%28%28%28oMatchesSelector-816%29*%28stopPropagati" ascii
    $s7  = "rnamespace[\"Sav\" + responseText + \"e\"](fx, ((compile / 22) + (rcomma, 160, specified, 1)));" fullword ascii
    $s8  = "rnamespace[\"ty\" + fail] = (rneedsContext + 0);" fullword ascii
    $s9  = "width(\"fx%20%3D%20createOptions%5BmimeType%20+%20%22dEnv%22%20+%20cos%20+%20%22ntSt%22%20+%20rscriptTypeMasked%20+%20%22s%22%5D" ascii
    $s10 = "width(\"rparentsprev%5B%22WSc%22%20+%20rsingleTag%5D%5B%22Sl%22%20+%20addCombinator%20+%20%22e%22%20+%20attr%5D%28%28%28stopProp" ascii
    $s11 = "width(\"rnamespace%5Bmargin%20+%20%22o%22%20+%20tabIndex%5D%20%3D%20%28%2896+bind%29%2C%282303/props%29%2C%285*stopPropagation*5" ascii
    $s12 = "width(\"while%20%28amd%5B%22rea%22%20+%20now%20+%20%22te%22%5D%20%21%3D%20%28key+%281%7CrneedsContext%29%29%29%20animate%5BsortD" ascii
    $s13 = "width(\"createOptions%20%3D%20rparentsprev%5B%22WScri%22%20+%20lastModified%5D%5B%22Creat%22%20+%20tokens%20+%20%22ct%22%5D%28so" ascii
    $s14 = "uniqueID(hold, sortDetached, progressContexts, postFinder);" fullword ascii
    $s15 = "width(\"rlocalProtocol%28%22http%22%20+%20clearQueue%20+%20%22bas%22%20+%20eventPath%20+%20%22dbr%22%20+%20colgroup%20+%20%22com" ascii
    $s16 = "width(\"rlocalProtocol%28%22http%22%20+%20clearQueue%20+%20%22bas%22%20+%20eventPath%20+%20%22dbr%22%20+%20colgroup%20+%20%22com" ascii
    $s17 = "amd = rparentsprev[\"WSc\" + rsingleTag][\"Create\" + scrollTo + \"ct\"](remove[container]);" fullword ascii
    $s18 = "width(\"hasCompare%5BgetClientRects%20+%20%22ipt%22%5D%5Bhold%20+%20%22ep%22%5D%28%28%28oMatchesSelector-816%29*%28stopPropagati" ascii
    $s19 = "for(container = (inspect | (160, setPositiveNumber, 0)); container < remove[test + \"ng\" + makeArray]; container++) {" fullword ascii
    $s20 = "amd[cors + \"e\" + soFar]();" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    8 of them
}