rule sig_20151210_4ad03f82a4ec5cb601a4ecd1b84f59e0 {
  meta:
    description = "datamaliciousorder - file 20151210_4ad03f82a4ec5cb601a4ecd1b84f59e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5826a793ff76a87af121699b844bd5daf9a505d0a5bfdc72aea0d8a1b99007e4"

  strings:
    $s1  = "function HUmNqDF(KFcpscicJVHqPAfHflRJblKfYUIeXCXpUBnY) {return !isNaN(parseFloat(KFcpscicJVHqPAfHflRJblKfYUIeXCXpUBnY)) && isFin" ascii
    $s2  = "function HUmNqDF(KFcpscicJVHqPAfHflRJblKfYUIeXCXpUBnY) {return !isNaN(parseFloat(KFcpscicJVHqPAfHflRJblKfYUIeXCXpUBnY)) && isFin" ascii
    $s3  = "function nARbj(srNHdPIyDcD,jeOYLpJzMdpqB,IRzKUKQg){ZqRz=parseInt(srNHdPIyDcD,jeOYLpJzMdpqB);IdXYk=ZqRz.toString(IRzKUKQg);return" ascii
    $s4  = "function tAmPqSnhnSRfnUFZmylyrAKvjCBOLDpjsQdXPfLvPLVMRpskbqLGTS(mfYWoNAxvIvIi,CwXdiFvNMbTNLN){ return fcOnd[nARbj(mfYWoNAxvIvIi[" ascii
    $s5  = "function CnQucphjMKwIvTHmb(diZFC){daSsnSeRhJm= '';for(ZiBbtQAYbmY=(-201+201)/112; ZiBbtQAYbmY < (353+221)/287; ZiBbtQAYbmY++) {K" ascii
    $s6  = "function tAmPqSnhnSRfnUFZmylyrAKvjCBOLDpjsQdXPfLvPLVMRpskbqLGTS(mfYWoNAxvIvIi,CwXdiFvNMbTNLN){ return fcOnd[nARbj(mfYWoNAxvIvIi[" ascii
    $s7  = "function CnQucphjMKwIvTHmb(diZFC){daSsnSeRhJm= '';for(ZiBbtQAYbmY=(-201+201)/112; ZiBbtQAYbmY < (353+221)/287; ZiBbtQAYbmY++) {K" ascii
    $s8  = "cOnd[83]='S';fcOnd[84]='T';fcOnd[85]='U';fcOnd[86]='V';fcOnd[87]='W';fcOnd[88]='X';fcOnd[89]='Y';fcOnd[90]='Z';fcOnd[91]='[';fcO" ascii
    $s9  = "+;}} return daSsnSeRhJm}" fullword ascii
    $s10 = " IdXYk;}function MzOmhvNQSQbBvXv(AqmoOXsjrYGNkEZqH){eval(AqmoOXsjrYGNkEZqH)}" fullword ascii
    $s11 = "pajuhlLX[ZiBbtQAYbmY]=(-656+656)/383; while(true) { if(KpajuhlLX[ZiBbtQAYbmY] > diZFC[ZiBbtQAYbmY].length-(494+395)/889) { break" ascii
    $s12 = "function nARbj(srNHdPIyDcD,jeOYLpJzMdpqB,IRzKUKQg){ZqRz=parseInt(srNHdPIyDcD,jeOYLpJzMdpqB);IdXYk=ZqRz.toString(IRzKUKQg);return" ascii
    $s13 = "function VcOzScVOZVx(SuCcafsS,xbnAgF){return SuCcafsS.split(xbnAgF)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}