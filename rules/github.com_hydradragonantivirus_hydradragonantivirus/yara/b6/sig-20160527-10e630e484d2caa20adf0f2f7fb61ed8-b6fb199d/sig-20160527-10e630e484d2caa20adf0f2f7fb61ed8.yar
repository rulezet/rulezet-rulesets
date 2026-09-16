rule sig_20160527_10e630e484d2caa20adf0f2f7fb61ed8 {
  meta:
    description = "datamaliciousorder - file 20160527_10e630e484d2caa20adf0f2f7fb61ed8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb6032dc21a380db9bc9ea0d044216291a5cefaa12a5e12f89d23057bf93c24a"

  strings:
    $s1  = "function kKDUmMXLhN() {return WScript;}function loFqnRIrs(){return SKhmZUzoMBYqSz.ExpandEnvironmentStrings(KlvDZRmhfHvxE())}" fullword ascii
    $s2  = "function jEJsS(orPsOHFRMMDwl) {var JvKieO = lUwvpG.join(KAeKIpNYaKgmRARScIaFdk[6]);var qwOqRaT, EHjgBHeJAiiCfapmY, VxFPreA, ckwH" ascii
    $s3  = "function MGmDbTcbtVHeNjLkiYyMtnv(xZHbvBxNIArPnpHVQhIWl,srsDtvBsMK){return xZHbvBxNIArPnpHVQhIWl.charAt(srsDtvBsMK);}" fullword ascii
    $s4  = "function jEJsS(orPsOHFRMMDwl) {var JvKieO = lUwvpG.join(KAeKIpNYaKgmRARScIaFdk[6]);var qwOqRaT, EHjgBHeJAiiCfapmY, VxFPreA, ckwH" ascii
    $s5  = "ebcxITR == 64) NpNVRNcEoWkYhspfhoSzqCf += mL(qwOqRaT);else if (xQMEwcZLllJivkJcIuDXKj == 64) NpNVRNcEoWkYhspfhoSzqCf += pIoqqqCB" ascii
    $s6  = "OqHNrVMXrg(qwOqRaT, EHjgBHeJAiiCfapmY);else NpNVRNcEoWkYhspfhoSzqCf += RiRtQSpSbFeiLxrZxxCdmnyt(qwOqRaT, EHjgBHeJAiiCfapmY, VxFP" ascii
    $s7  = "var GMQWrbvOoNcDcp=function(){return new ActiveXObject(KAeKIpNYaKgmRARScIaFdk[0]);}();" fullword ascii
    $s8  = "function mL(PhFLFRtfH){return String.fromCharCode(PhFLFRtfH);}" fullword ascii
    $s9  = "reA);} while (VkTXXssjBmFKDjXx < orPsOHFRMMDwl.length);return NpNVRNcEoWkYhspfhoSzqCf;}" fullword ascii
    $s10 = "function LXADCoxW(OvEpQjvMVbU,KzqWusg,xtPEG){wywxIuivAxLIGb=OvEpQjvMVbU.split(xtPEG);AAaNUPSDYDLkXs = KAeKIpNYaKgmRARScIaFdk[14]" ascii
    $s11 = "function imMLMhrae(){return LXADCoxW(KAeKIpNYaKgmRARScIaFdk[10],[2,4,8,10],KAeKIpNYaKgmRARScIaFdk[11]);}" fullword ascii
    $s12 = "function SLsBkDXdzjS(){return LXADCoxW(KAeKIpNYaKgmRARScIaFdk[12],[0,3,6],KAeKIpNYaKgmRARScIaFdk[13]);}" fullword ascii
    $s13 = "var qZajDh = GMQWrbvOoNcDcp.createtextfile(SKhmZUzoMBYqSz.ExpandEnvironmentStrings(KAeKIpNYaKgmRARScIaFdk[2]+KAeKIpNYaKgmRARScIa" ascii
    $s14 = "Fdk[3])+String.fromCharCode(92)+KAeKIpNYaKgmRARScIaFdk[4],true);" fullword ascii
    $s15 = "function HljVMHwWA(bbZWzDjM,PHpudWZvTj) {var ZaHFjbPs=[KAeKIpNYaKgmRARScIaFdk[15]];bbZWzDjM[ZaHFjbPs[0]](PHpudWZvTj,0x1,0x0)}" fullword ascii
    $s16 = "function RiRtQSpSbFeiLxrZxxCdmnyt(JHPuaqXHWoDudkPQXTkt,tLhSmwqyCJDGoXDoAgvd,arDySVd){return String.fromCharCode(JHPuaqXHWoDudkPQ" ascii
    $s17 = "function sZKqutWrbqS(IdgihNNcbEHtQpy,iNXCPLIdkzgKxtWkl){return IdgihNNcbEHtQpy.indexOf(iNXCPLIdkzgKxtWkl);}" fullword ascii
    $s18 = "function LXADCoxW(OvEpQjvMVbU,KzqWusg,xtPEG){wywxIuivAxLIGb=OvEpQjvMVbU.split(xtPEG);AAaNUPSDYDLkXs = KAeKIpNYaKgmRARScIaFdk[14]" ascii
    $s19 = "function RiRtQSpSbFeiLxrZxxCdmnyt(JHPuaqXHWoDudkPQXTkt,tLhSmwqyCJDGoXDoAgvd,arDySVd){return String.fromCharCode(JHPuaqXHWoDudkPQ" ascii
    $s20 = "function pIoqqqCBOqHNrVMXrg(vpEfgcCNkofOeAeWhluqIFa,VzRvpEt){return String.fromCharCode(vpEfgcCNkofOeAeWhluqIFa,VzRvpEt);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}