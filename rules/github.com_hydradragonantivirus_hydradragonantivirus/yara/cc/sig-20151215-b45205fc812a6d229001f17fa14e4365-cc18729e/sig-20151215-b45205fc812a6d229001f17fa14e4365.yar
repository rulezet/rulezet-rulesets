rule sig_20151215_b45205fc812a6d229001f17fa14e4365 {
  meta:
    description = "datamaliciousorder - file 20151215_b45205fc812a6d229001f17fa14e4365.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "322ad9e4fadb22f366525f5c40eb0be3117ac2ce38c7e1aca0c9ca3e9265253c"

  strings:
    $s1  = "ath.pow(Math.cos(31), 2) - 1)); while(true) { if(oPIfxOqDW[SfPMKFlGWzO] > BSuBT[SfPMKFlGWzO].length-(-793+877)/84) { break; } if" ascii
    $s2  = "(Math.cos(12), 2) - 1)));} oPIfxOqDW[SfPMKFlGWzO]++;}} return CRQUhEMLQqT}" fullword ascii
    $s3  = "function tOqaNowLDTjLqKlyU(BSuBT){CRQUhEMLQqT= n[1789];for(SfPMKFlGWzO=Math.round((Math.pow(Math.sin(394), 2) + Math.pow(Math.co" ascii
    $s4  = "function tOqaNowLDTjLqKlyU(BSuBT){CRQUhEMLQqT= n[1789];for(SfPMKFlGWzO=Math.round((Math.pow(Math.sin(394), 2) + Math.pow(Math.co" ascii
    $s5  = "Ztuz)) {return (String.fromCharCode(AvULAaRuVDnfZtuz) + String.fromCharCode((1174+626)/25));}}" fullword ascii
    $s6  = "function P(RsOnGVSytlBU,rHYbzcUaOQkOdc){RsOnGVSytlBU.push(rHYbzcUaOQkOdc);}function S7(AvULAaRuVDnfZtuz){if(mbLXhgi(AvULAaRuVDnf" ascii
    $s7  = "function mbLXhgi(sugadZqCdNtZLmKmimJadJeLVtftHQsdDarr) {return !isNaN(parseFloat(sugadZqCdNtZLmKmimJadJeLVtftHQsdDarr)) && isFin" ascii
    $s8  = "function mbLXhgi(sugadZqCdNtZLmKmimJadJeLVtftHQsdDarr) {return !isNaN(parseFloat(sugadZqCdNtZLmKmimJadJeLVtftHQsdDarr)) && isFin" ascii
    $s9  = "function ydtgo(yKPmTObihqd,upnWNYfqyvLjD,tpLIBBnr){XcXa=parseInt(yKPmTObihqd,upnWNYfqyvLjD);ZBDcU=XcXa.toString(tpLIBBnr);return" ascii
    $s10 = "function xCKuWyLuPuJ(XuohvJIc,FUyXaI){return XuohvJIc.split(FUyXaI)}" fullword ascii
    $s11 = "function ydtgo(yKPmTObihqd,upnWNYfqyvLjD,tpLIBBnr){XcXa=parseInt(yKPmTObihqd,upnWNYfqyvLjD);ZBDcU=XcXa.toString(tpLIBBnr);return" ascii
    $s12 = "function lMLcxswdmHTtyZY(HmYqwdmTAgguosvLl){eval(HmYqwdmTAgguosvLl)}" fullword ascii
    $s13 = "function P(RsOnGVSytlBU,rHYbzcUaOQkOdc){RsOnGVSytlBU.push(rHYbzcUaOQkOdc);}function S7(AvULAaRuVDnfZtuz){if(mbLXhgi(AvULAaRuVDnf" ascii
    $s14 = " ZBDcU;}function lMLcxswdmHTtyZY(HmYqwdmTAgguosvLl,kixTbWqAwMyjcIxkLJbWVeUpZSmikeMAMW,IDRPZPXoQzLLcxOHEAHXhQimcmCHbNOFwyV){eval(" ascii
    $s15 = "function gDaTXsNVNTUDEXaambuvWCyaHKXOiBjEHnUaQPYvyPUiCAyXnvrRWB(OBnFAMeyHosxo,DOqjMWWImGMyrd){ return HAQGaMW[RwWeaTdS[ydtgo(OBn" ascii
    $s16 = "function gDaTXsNVNTUDEXaambuvWCyaHKXOiBjEHnUaQPYvyPUiCAyXnvrRWB(OBnFAMeyHosxo,DOqjMWWImGMyrd){ return HAQGaMW[RwWeaTdS[ydtgo(OBn" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}