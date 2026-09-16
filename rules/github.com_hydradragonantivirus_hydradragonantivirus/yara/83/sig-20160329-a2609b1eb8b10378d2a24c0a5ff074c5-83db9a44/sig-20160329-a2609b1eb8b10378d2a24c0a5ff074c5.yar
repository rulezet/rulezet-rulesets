rule sig_20160329_a2609b1eb8b10378d2a24c0a5ff074c5 {
  meta:
    description = "datamaliciousorder - file 20160329_a2609b1eb8b10378d2a24c0a5ff074c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0a70861a5adee0b716ee0730f78cb13f3804c2d9b466ad1832f87a6604e9966"

  strings:
    $s1  = " root(\"rclickable%20%3D%20lock%5B%22Expan%22%20+%20host%20+%20%22ron%22%20+%20div%20+%20%22Strin%22%20+%20constructor%5D%28%22%" ascii
    $s2  = " root(\"ajaxHandleResponses%28rbuggyQSA%20+%20%22//azc%22%20+%20prefilterOrFactory%20+%20%22tsu%22%20+%20responseHeadersString%2" ascii
    $s3  = " root(\"lock%20%3D%20currentValue%5B%22WSc%22%20+%20getScript%20+%20%22t%22%5D%5Bgroups%20+%20%22Object%22%5D%28visibility%20+%2" ascii
    $s4  = "  currentValue[\"WScri\" + preFilters][\"Slee\" + handlerQueue](((Math.pow(3769, headers) - 14200489) | (Math.pow(camel, 2) - em" ascii
    $s5  = "  currentValue[\"WScri\" + preFilters][\"Slee\" + handlerQueue](((Math.pow(3769, headers) - 14200489) | (Math.pow(camel, 2) - em" ascii
    $s6  = " root(\"cloneCopyEvent%5Btime%20+%20%22e%22%20+%20getById%5D%28%22GE%22%20+%20run%2C%20%22http%22%20+%20rnoInnerhtml%20+%20%22ar" ascii
    $s7  = " root(\"lock%20%3D%20currentValue%5B%22WSc%22%20+%20getScript%20+%20%22t%22%5D%5Bgroups%20+%20%22Object%22%5D%28visibility%20+%2" ascii
    $s8  = " root(\"cloneCopyEvent%5Btime%20+%20%22e%22%20+%20getById%5D%28%22GE%22%20+%20run%2C%20%22http%22%20+%20rnoInnerhtml%20+%20%22ar" ascii
    $s9  = " root(\"while%20%28cloneCopyEvent%5Bload%20+%20%22ySt%22%20+%20state%5D%20%21%3D%20%28%286-elemLang%29*%28143%2Clang%2C221%2Chea" ascii
    $s10 = "  lock[\"Ru\" + getById](rclickable);" fullword ascii
    $s11 = " root(\"rclickable%20%3D%20lock%5B%22Expan%22%20+%20host%20+%20%22ron%22%20+%20div%20+%20%22Strin%22%20+%20constructor%5D%28%22%" ascii
    $s12 = " root(\"while%20%28cloneCopyEvent%5Bload%20+%20%22ySt%22%20+%20state%5D%20%21%3D%20%28%286-elemLang%29*%28143%2Clang%2C221%2Chea" ascii
    $s13 = " if(cloneCopyEvent[focus + \"atu\" + max] == ((562 + param) / (22 - col))) {" fullword ascii
    $s14 = " root(\"ajaxHandleResponses%28rbuggyQSA%20+%20%22//azc%22%20+%20prefilterOrFactory%20+%20%22tsu%22%20+%20responseHeadersString%2" ascii
    $s15 = " root(\"scrollLeft%20%3D%20%5B%22Msx%22%20+%20responseFields%20+%20%22rverX%22%20+%20bindType%20+%20%22.6.0%22%2C%20when%20+%20%" ascii
    $s16 = " root(\"checkbox%5B%22WScrip%22%20+%20camelKey%5D%5B%22Sle%22%20+%20access%5D%28%28%28script*5+define%29%7C%28768%7Ctuple%29%29%" ascii
    $s17 = " root(\"checkbox%5B%22WScrip%22%20+%20camelKey%5D%5B%22Sle%22%20+%20access%5D%28%28%28script*5+define%29%7C%28768%7Ctuple%29%29%" ascii
    $s18 = "raw[\"t\" + container + \"e\"] = ((197, hasData) | (1 * hasData));" fullword ascii
    $s19 = "raw[nonce + \"od\" + mapped] = (3 & traditional);" fullword ascii
    $s20 = " root(\"raw%20%3D%20w%5B%22WScri%22%20+%20preFilters%5D%5B%22Cre%22%20+%20state%20+%20%22Obj%22%20+%20rdisplayswap%5D%28%22ADODB" ascii

  condition:
    uint16(0) == 0x6372 and
    8 of them
}