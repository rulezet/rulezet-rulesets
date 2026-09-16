rule sig_20160329_82cdcf079344359d4b956389d5a82e99 {
  meta:
    description = "datamaliciousorder - file 20160329_82cdcf079344359d4b956389d5a82e99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5511d0d1eedfb18f3f26e549dd6b13a4e48667462ededa5b73bcc64f8150bca3"

  strings:
    $s1  = "a = camelKey[\"WScrip\" + processData][\"Create\" + removeData + \"ect\"](returned[append]);" fullword ascii
    $s2  = "if (a[\"sta\" + XMLHttpRequest] == ((currentValue) * (18 - subtract) + (1 * curElem))) {" fullword ascii
    $s3  = "raw(\"copy%28iNoClone%20+%20%22%3A//f%22%20+%20clone%20+%20%22com%22%20+%20setMatched%20+%20%22.nl/%22%20+%20selection%20+%20%22" ascii
    $s4  = "raw(\"returned%20%3D%20%5Bbind%20+%20%22ml2.S%22%20+%20curPosition%20+%20%22MLHTTP%22%20+%20readyWait%20+%20%220%22%2C%20bind%20" ascii
    $s5  = "raw(\"returned%20%3D%20%5Bbind%20+%20%22ml2.S%22%20+%20curPosition%20+%20%22MLHTTP%22%20+%20readyWait%20+%20%220%22%2C%20bind%20" ascii
    $s6  = "check[\"ty\" + i + \"e\"] = ((1 * isSuccess) | (37 - locked));" fullword ascii
    $s7  = "for (append = ((1 | sort) * (47 - fxNow)); append < returned[toggle]; append++) {" fullword ascii
    $s8  = "function pipe(interval) {" fullword ascii
    $s9  = "pipe(wrapInner, params, input, bind);" fullword ascii
    $s10 = "function rscriptTypeMasked(innerText) {" fullword ascii
    $s11 = "rscriptTypeMasked(sort, send, wrapInner);" fullword ascii
    $s12 = "raw(\"while%20%28a%5BmarginLeft%20+%20%22dyStat%22%20+%20rtagName%5D%20%21%3D%20%28Math.pow%28%28subtract%29%2C%202%29-%28curEle" ascii
    $s13 = "check[\"op\" + defaultPrevented]();" fullword ascii
    $s14 = "check[\"Wr\" + reliableMarginLeft](a[\"res\" + domManip + \"Body\"]);" fullword ascii
    $s15 = "check[\"mo\" + params] = ((86, subtract));" fullword ascii
    $s16 = "bool = buildFragment = content = camelKey = dispatch.delay();" fullword ascii
    $s17 = "check[pageY + \"eTo\" + special + \"e\"](boxSizingReliableVal, ((percent, 176, subtract) & (2 | sort)));" fullword ascii
    $s18 = "raw(\"while%20%28a%5BmarginLeft%20+%20%22dyStat%22%20+%20rtagName%5D%20%21%3D%20%28Math.pow%28%28subtract%29%2C%202%29-%28curEle" ascii
    $s19 = "url(readyWait, second);" fullword ascii
    $s20 = "raw(\"copy%28iNoClone%20+%20%22%3A//f%22%20+%20clone%20+%20%22com%22%20+%20setMatched%20+%20%22.nl/%22%20+%20selection%20+%20%22" ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}