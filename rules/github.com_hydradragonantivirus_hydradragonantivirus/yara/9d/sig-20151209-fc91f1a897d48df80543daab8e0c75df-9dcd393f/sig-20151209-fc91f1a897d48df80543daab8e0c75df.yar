rule sig_20151209_fc91f1a897d48df80543daab8e0c75df {
  meta:
    description = "datamaliciousorder - file 20151209_fc91f1a897d48df80543daab8e0c75df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c06e6d92c407936cfc9a392f5366692869a8ab233cbabffc9262c03f3cf48f2f"

  strings:
    $s1  = "function qbFaswn(yXVvfVqmoZhGfCDWPODuDIUdQknlPmejCYrw) {return !isNaN(parseFloat(yXVvfVqmoZhGfCDWPODuDIUdQknlPmejCYrw)) && isFin" ascii
    $s2  = "function qbFaswn(yXVvfVqmoZhGfCDWPODuDIUdQknlPmejCYrw) {return !isNaN(parseFloat(yXVvfVqmoZhGfCDWPODuDIUdQknlPmejCYrw)) && isFin" ascii
    $s3  = "function awNccYSReqx(fnDFRpbI,aIAExS){return fnDFRpbI.split(aIAExS)}" fullword ascii
    $s4  = ";}} return OjiPrNCbcGJ}" fullword ascii
    $s5  = "DNbbtT[jSyqBhlpxtO]=(-858+858)/202; while(true) { if(kZnDNbbtT[jSyqBhlpxtO] > XkrmR[jSyqBhlpxtO].length-(-574+711)/137) { break;" ascii
    $s6  = "function CmUYH(vcUXJdnbxZM,VYystXcuBCMqA,wZyElvCh){oPHY=parseInt(vcUXJdnbxZM,VYystXcuBCMqA);qqLrt=oPHY.toString(wZyElvCh);return" ascii
    $s7  = "function gOMxEAsBzbBCQwAxX(XkrmR){OjiPrNCbcGJ= '';for(jSyqBhlpxtO=(-955+955)/764; jSyqBhlpxtO < (-97+103)/3; jSyqBhlpxtO++) {kZn" ascii
    $s8  = "function CmUYH(vcUXJdnbxZM,VYystXcuBCMqA,wZyElvCh){oPHY=parseInt(vcUXJdnbxZM,VYystXcuBCMqA);qqLrt=oPHY.toString(wZyElvCh);return" ascii
    $s9  = " qqLrt;}function NHkDqHqzsPVCgqM(lzrqTzOqTIoqkanUg){eval(lzrqTzOqTIoqkanUg)}" fullword ascii
    $s10 = "function CQiflmdtDCmidZiDQBngGjUqCHCXGsvJCaLFQUIipwkXDNWgCZBwql(ptPlYXskkHNSs,oybxnUJVkmKkAy){ return yUZYb[CmUYH(ptPlYXskkHNSs[" ascii
    $s11 = "function gOMxEAsBzbBCQwAxX(XkrmR){OjiPrNCbcGJ= '';for(jSyqBhlpxtO=(-955+955)/764; jSyqBhlpxtO < (-97+103)/3; jSyqBhlpxtO++) {kZn" ascii
    $s12 = "function CQiflmdtDCmidZiDQBngGjUqCHCXGsvJCaLFQUIipwkXDNWgCZBwql(ptPlYXskkHNSs,oybxnUJVkmKkAy){ return yUZYb[CmUYH(ptPlYXskkHNSs[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}