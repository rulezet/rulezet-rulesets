rule sig_20151215_b62dd0010a63dbf67f5303e0437001fd {
  meta:
    description = "datamaliciousorder - file 20151215_b62dd0010a63dbf67f5303e0437001fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f96f5f261edbdd0e72000a015a75d01f87968b6856efbcfebe2489e52c7eb2b"

  strings:
    $s1  = "ow(Math.cos(343), 2) - 1)));} lXdZsVMvB[GwEklrezRuW]++;}} return bxvjfuwJtay}" fullword ascii
    $s2  = "function bElIwlGXAuSZYGeRl(OJqJM){bxvjfuwJtay= U[1755];for(GwEklrezRuW=Math.round((Math.pow(Math.sin(183), 2) + Math.pow(Math.co" ascii
    $s3  = "th.pow(Math.cos(285), 2) - 1)); while(true) { if(lXdZsVMvB[GwEklrezRuW] > OJqJM[GwEklrezRuW].length-(317+614)/931) { break; } if" ascii
    $s4  = "function bElIwlGXAuSZYGeRl(OJqJM){bxvjfuwJtay= U[1755];for(GwEklrezRuW=Math.round((Math.pow(Math.sin(183), 2) + Math.pow(Math.co" ascii
    $s5  = "function e(sldfcMRGKkZG,dmricNAUWJOGrG){sldfcMRGKkZG.push(dmricNAUWJOGrG);}function Z8(pqOcYUJmKQqjDQWB){if(TsiCOeH(pqOcYUJmKQqj" ascii
    $s6  = "DQWB)) {return (String.fromCharCode(pqOcYUJmKQqjDQWB) + String.fromCharCode((17172+222)/223));}}" fullword ascii
    $s7  = "function TsiCOeH(NzXsufybbQQBbTFuYYuejbuXWAoTiZORvuTQ) {return !isNaN(parseFloat(NzXsufybbQQBbTFuYYuejbuXWAoTiZORvuTQ)) && isFin" ascii
    $s8  = "function TsiCOeH(NzXsufybbQQBbTFuYYuejbuXWAoTiZORvuTQ) {return !isNaN(parseFloat(NzXsufybbQQBbTFuYYuejbuXWAoTiZORvuTQ)) && isFin" ascii
    $s9  = "var U=new Array();" fullword ascii
    $s10 = "function TCzJtgvcVJUaaeQ(aZLjleTkAHFdlAfYu){eval(aZLjleTkAHFdlAfYu)}" fullword ascii
    $s11 = "function LEvhQNxEVtC(WTMEVzOP,WkcDZL){return WTMEVzOP.split(WkcDZL)}" fullword ascii
    $s12 = "function dXBVW(JYjUToNlyfZ,yMEsbHLWlsPIz,OshVhDMa){QvdQ=parseInt(JYjUToNlyfZ,yMEsbHLWlsPIz);XYZxV=QvdQ.toString(OshVhDMa);return" ascii
    $s13 = "function dXBVW(JYjUToNlyfZ,yMEsbHLWlsPIz,OshVhDMa){QvdQ=parseInt(JYjUToNlyfZ,yMEsbHLWlsPIz);XYZxV=QvdQ.toString(OshVhDMa);return" ascii
    $s14 = "function e(sldfcMRGKkZG,dmricNAUWJOGrG){sldfcMRGKkZG.push(dmricNAUWJOGrG);}function Z8(pqOcYUJmKQqjDQWB){if(TsiCOeH(pqOcYUJmKQqj" ascii
    $s15 = " XYZxV;}function TCzJtgvcVJUaaeQ(aZLjleTkAHFdlAfYu,LuweUQJtRiEDYrWddzNeOqXGDxfhseikVg,VuRocjajwqYQZOCsuUaNfhDLZnXLcEGbocG){eval(" ascii
    $s16 = "function NCesdwjIqTCcDQkzuotTFmNIJpuDMTgMMjHxteszOVZglLGRZIZiuO(WbxWQzEidNdww,GvorInwPMwJvpq){ return jxmYLpv[eXlWOpsA[dXBVW(Wbx" ascii
    $s17 = "function NCesdwjIqTCcDQkzuotTFmNIJpuDMTgMMjHxteszOVZglLGRZIZiuO(WbxWQzEidNdww,GvorInwPMwJvpq){ return jxmYLpv[eXlWOpsA[dXBVW(Wbx" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}