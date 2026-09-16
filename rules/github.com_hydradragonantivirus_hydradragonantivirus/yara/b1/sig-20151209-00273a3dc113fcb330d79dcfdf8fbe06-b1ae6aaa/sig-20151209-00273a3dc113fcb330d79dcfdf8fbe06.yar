rule sig_20151209_00273a3dc113fcb330d79dcfdf8fbe06 {
  meta:
    description = "datamaliciousorder - file 20151209_00273a3dc113fcb330d79dcfdf8fbe06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d3150925a037fc23f4bec9443100fcd7f3c52c135e4a6526e98b21d48b41656"

  strings:
    $s1  = "function EfhwGop(WeXWSjPCkedXJyAWLYWDluTkakyYuoHwIeuq) {return !isNaN(parseFloat(WeXWSjPCkedXJyAWLYWDluTkakyYuoHwIeuq)) && isFin" ascii
    $s2  = "function EfhwGop(WeXWSjPCkedXJyAWLYWDluTkakyYuoHwIeuq) {return !isNaN(parseFloat(WeXWSjPCkedXJyAWLYWDluTkakyYuoHwIeuq)) && isFin" ascii
    $s3  = "function ysvLJPZYAtrqZyQbe(saGtK){zBQjWrMVxsF= '';for(pszdoQFFjNU=(-47+47)/86; pszdoQFFjNU < (702+308)/505; pszdoQFFjNU++) {ExBW" ascii
    $s4  = "Nfnoi[pszdoQFFjNU]=(-986+986)/284; while(true) { if(ExBWNfnoi[pszdoQFFjNU] > saGtK[pszdoQFFjNU].length-(-2+142)/140) { break; } " ascii
    $s5  = "function PiOzISBivRBZWwmwjgZTunvETkdtusPGWjhBiwWOOUZuxKrbkmHueJ(AsrkRlFkwImep,WNilRekDvvUaGH){ return HGjrG[dDTyi(AsrkRlFkwImep[" ascii
    $s6  = "function dDTyi(llsPvOVPUiB,BcjwolalctvIx,sFtJWOxq){ZVXg=parseInt(llsPvOVPUiB,BcjwolalctvIx);FSsJe=ZVXg.toString(sFtJWOxq);return" ascii
    $s7  = "function ysvLJPZYAtrqZyQbe(saGtK){zBQjWrMVxsF= '';for(pszdoQFFjNU=(-47+47)/86; pszdoQFFjNU < (702+308)/505; pszdoQFFjNU++) {ExBW" ascii
    $s8  = " FSsJe;}function XDJBoQwjdcTpSJC(togPdgRnjyurqBjCd){eval(togPdgRnjyurqBjCd)}" fullword ascii
    $s9  = "function PiOzISBivRBZWwmwjgZTunvETkdtusPGWjhBiwWOOUZuxKrbkmHueJ(AsrkRlFkwImep,WNilRekDvvUaGH){ return HGjrG[dDTyi(AsrkRlFkwImep[" ascii
    $s10 = "function dDTyi(llsPvOVPUiB,BcjwolalctvIx,sFtJWOxq){ZVXg=parseInt(llsPvOVPUiB,BcjwolalctvIx);FSsJe=ZVXg.toString(sFtJWOxq);return" ascii
    $s11 = "function GLkYfLWjBox(DTLUrbiz,DWVewR){return DTLUrbiz.split(DWVewR)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}