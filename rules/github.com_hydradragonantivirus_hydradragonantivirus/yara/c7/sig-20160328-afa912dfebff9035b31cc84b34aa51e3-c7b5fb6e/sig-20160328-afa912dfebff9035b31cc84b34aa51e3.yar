rule sig_20160328_afa912dfebff9035b31cc84b34aa51e3 {
  meta:
    description = "datamaliciousorder - file 20160328_afa912dfebff9035b31cc84b34aa51e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "203e36486fc9c48687f3ca3391773ec05f078dc5b771aac11e87a858a230ce7f"

  strings:
    $s1  = "eval(count(\"transports%20%3D%20%28%22rep%22%29%2C%20open%20%3D%20%28%22s%22%29%2C%20filters%20%3D%20%28%22HTTP%22%29%2C%20clone" ascii
    $s2  = "computeStyleTests(count(\"eq%5Bparents%20+%20%22pe%22%20+%20nodeType%5D%28%22GE%22%20+%20appendChild%2C%20%22htt%22%20+%20getAtt" ascii
    $s3  = "rcssNum[\"WScri\" + prop][\"Sleep\"]((Math.pow((2853 & onreadystatechange), 2) - (second & 7861713)));" fullword ascii
    $s4  = "while(eq[\"readyS\" + compilerCache] != (Math.pow((rmouseEvent - 27), cssFn) - (1 * step))) rcssNum[\"WScri\" + prop][\"Sleep\"]" ascii
    $s5  = "while(eq[\"readyS\" + compilerCache] != (Math.pow((rmouseEvent - 27), cssFn) - (1 * step))) rcssNum[\"WScri\" + prop][\"Sleep\"]" ascii
    $s6  = "for(elementMatchers = ((Math.pow(155, cssFn) - 23869), (srcElements), (37 - animation)); elementMatchers < load[\"lengt\" + cont" ascii
    $s7  = "for(elementMatchers = ((Math.pow(155, cssFn) - 23869), (srcElements), (37 - animation)); elementMatchers < load[\"lengt\" + cont" ascii
    $s8  = "function scrollTop(els, delegateTarget, dataPriv) {" fullword ascii
    $s9  = "computeStyleTests(count(\"name%5B%22WScr%22%20+%20cloneCopyEvent%5D%5B%22S%22%20+%20currentTime%20+%20%22ee%22%20+%20fixHooks%5D" ascii
    $s10 = "constructor[offset + \"pe\"] = ((74 - clearCloneStyle) / (650 / col));" fullword ascii
    $s11 = "computeStyleTests(count(\"eq%5Bparents%20+%20%22pe%22%20+%20nodeType%5D%28%22GE%22%20+%20appendChild%2C%20%22htt%22%20+%20getAtt" ascii
    $s12 = "computeStyleTests(count(\"position%20%3D%20init%5B%22Expan%22%20+%20getClass%20+%20%22viron%22%20+%20nodeNameSelector%20+%20%22t" ascii
    $s13 = "eq = matchExpr[\"WScr\" + cloneCopyEvent][\"Create\" + compile + \"ect\"](load[elementMatchers]);" fullword ascii
    $s14 = "eval(count(\"transports%20%3D%20%28%22rep%22%29%2C%20open%20%3D%20%28%22s%22%29%2C%20filters%20%3D%20%28%22HTTP%22%29%2C%20clone" ascii
    $s15 = "computeStyleTests(count(\"load%20%3D%20%5B%22Msxml2%22%20+%20style%20+%20%22verXM%22%20+%20reject%20+%20%22.6.0%22%2C%20htmlPref" ascii
    $s16 = "computeStyleTests(count(\"position%20%3D%20init%5B%22Expan%22%20+%20getClass%20+%20%22viron%22%20+%20nodeNameSelector%20+%20%22t" ascii
    $s17 = "constructor[parents + \"pe\" + nodeType]();" fullword ascii
    $s18 = "if(eq[context + \"tus\"] == ((118 + fromCharCode) - (244 & removeClass))) {" fullword ascii
    $s19 = "init[parseFromString + \"n\"](position);" fullword ascii
    $s20 = "computeStyleTests(count(\"constructor%5B%22SaveTo%22%20+%20replaceChild%5D%28position%2C%20%28%28rneedsContext%7C66%29%2C%28amd*" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}