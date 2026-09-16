rule sig_20151211_df7af2b9d8d39e685ee394038bba2a40 {
  meta:
    description = "datamaliciousorder - file 20151211_df7af2b9d8d39e685ee394038bba2a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6542f06fd38de4d08c752b05451793a1eda22288c7b779da5b241ffe722d5ea7"

  strings:
    $s1  = " oPLkW;}function QkptlztozgrGgwo(bHRiwmgSXbRaoZTGj){eval(bHRiwmgSXbRaoZTGj)}" fullword ascii
    $s2  = "var e=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4k\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s3  = "function iNaCfLVqzQYENRtRyyCWMRhPSIoLFvPexOZzNJtjdpKWMpWFDSrvob(TsbZtXOCCUJYx,nvvZNSxNcUSaEs){ return jIVxN[IahiR(TsbZtXOCCUJYx[" ascii
    $s4  = "function IahiR(fagIlMElYRU,aDKdueFbzTnUB,wxnEvHzo){FsoP=parseInt(fagIlMElYRU,aDKdueFbzTnUB);oPLkW=FsoP.toString(wxnEvHzo);return" ascii
    $s5  = "function iNaCfLVqzQYENRtRyyCWMRhPSIoLFvPexOZzNJtjdpKWMpWFDSrvob(TsbZtXOCCUJYx,nvvZNSxNcUSaEs){ return jIVxN[IahiR(TsbZtXOCCUJYx[" ascii
    $s6  = ";ndZRjYRQt[rbwRMnpqkSX]=(-336+336)/739; while(true) { if(ndZRjYRQt[rbwRMnpqkSX] > yjRJL[rbwRMnpqkSX].length-(-89+188)/99) { brea" ascii
    $s7  = "function HswKrJgREcF(qolbfxtI,xMDMHd){return qolbfxtI.split(xMDMHd)}" fullword ascii
    $s8  = "var P=new Array(\"2c\",\"28\",\"28\",\"26\",\"2c\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s9  = "var e=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4k\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = "var P=new Array(\"2c\",\"28\",\"28\",\"26\",\"2c\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s11 = "function IahiR(fagIlMElYRU,aDKdueFbzTnUB,wxnEvHzo){FsoP=parseInt(fagIlMElYRU,aDKdueFbzTnUB);oPLkW=FsoP.toString(wxnEvHzo);return" ascii
    $s12 = "function KrSnphm(hHqTEMdpEsdHcopBymAdCkbtYdYKFMGBySca) {return !isNaN(parseFloat(hHqTEMdpEsdHcopBymAdCkbtYdYKFMGBySca)) && isFin" ascii
    $s13 = "function KrSnphm(hHqTEMdpEsdHcopBymAdCkbtYdYKFMGBySca) {return !isNaN(parseFloat(hHqTEMdpEsdHcopBymAdCkbtYdYKFMGBySca)) && isFin" ascii
    $s14 = "function LmflipnCEdpEzhptu(yjRJL){RcAWaQIcQsr= '';rbwRMnpqkSX=(-485+485)/993; while(true){if(rbwRMnpqkSX >= (-656+858)/101)break" ascii
    $s15 = ";}rbwRMnpqkSX++;} return RcAWaQIcQsr}" fullword ascii
    $s16 = "function LmflipnCEdpEzhptu(yjRJL){RcAWaQIcQsr= '';rbwRMnpqkSX=(-485+485)/993; while(true){if(rbwRMnpqkSX >= (-656+858)/101)break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}