rule sig_20151214_a60153f30072e1ff1e97c1663f894c83 {
  meta:
    description = "datamaliciousorder - file 20151214_a60153f30072e1ff1e97c1663f894c83.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6a298aa8ac8cd6621e793dd85ccf02286be98f24b8f74edc17305edfbb7efed"

  strings:
    $s1  = "ath.pow(Math.cos(546), 2) - 1)); while(true) { if(iiGjDtbpO[RYfNiljFYTL] > xHEnd[RYfNiljFYTL].length-(-467+935)/468) { break; } " ascii
    $s2  = "function OZpAxOHJtyygBgqpD(xHEnd){fsZjGnSkjzY= P[1797];for(RYfNiljFYTL=Math.round((Math.pow(Math.sin(114), 2) + Math.pow(Math.co" ascii
    $s3  = "ow(Math.cos(400), 2) - 1)));} iiGjDtbpO[RYfNiljFYTL]++;}} return fsZjGnSkjzY}" fullword ascii
    $s4  = "function OZpAxOHJtyygBgqpD(xHEnd){fsZjGnSkjzY= P[1797];for(RYfNiljFYTL=Math.round((Math.pow(Math.sin(114), 2) + Math.pow(Math.co" ascii
    $s5  = "function CnreVZKDBbtvpYajEyQWokhkEDFdDMPpmmwFSfkHaoyrmabHQoRdHn(EvILuZZwKoMcM,lhWAkFIlelVMHn){ return RgTRNbb[WwAgcjFA[VwBjU(EvI" ascii
    $s6  = "function CnreVZKDBbtvpYajEyQWokhkEDFdDMPpmmwFSfkHaoyrmabHQoRdHn(EvILuZZwKoMcM,lhWAkFIlelVMHn){ return RgTRNbb[WwAgcjFA[VwBjU(EvI" ascii
    $s7  = "function x(JpgwQjRGtVWJ,LhOSNJfwZSDMYn){JpgwQjRGtVWJ.push(LhOSNJfwZSDMYn);}function u9(oaXLfhSKzEaKcFcu){if(yCZsmNI(oaXLfhSKzEaK" ascii
    $s8  = "cFcu)) {return (String.fromCharCode(oaXLfhSKzEaKcFcu) + String.fromCharCode((4887+542)/89));}}" fullword ascii
    $s9  = "function yCZsmNI(yqKcRImeWMMjfTciqfkmainNdjHbgdGpgxWE) {return !isNaN(parseFloat(yqKcRImeWMMjfTciqfkmainNdjHbgdGpgxWE)) && isFin" ascii
    $s10 = "function yCZsmNI(yqKcRImeWMMjfTciqfkmainNdjHbgdGpgxWE) {return !isNaN(parseFloat(yqKcRImeWMMjfTciqfkmainNdjHbgdGpgxWE)) && isFin" ascii
    $s11 = "var P=new Array();" fullword ascii
    $s12 = "function x(JpgwQjRGtVWJ,LhOSNJfwZSDMYn){JpgwQjRGtVWJ.push(LhOSNJfwZSDMYn);}function u9(oaXLfhSKzEaKcFcu){if(yCZsmNI(oaXLfhSKzEaK" ascii
    $s13 = "function pDhghplRGLxOFFd(WZilHNtXOJFBvDFQW){eval(WZilHNtXOJFBvDFQW)}" fullword ascii
    $s14 = "function VwBjU(btLADsOiNPd,mGAnqUHpNkjik,ImYjzYgC){KDEn=parseInt(btLADsOiNPd,mGAnqUHpNkjik);saOsn=KDEn.toString(ImYjzYgC);return" ascii
    $s15 = " saOsn;}function pDhghplRGLxOFFd(WZilHNtXOJFBvDFQW,kOpcXwniQpAovzZpTpnjAlBuQHJJSgsBja,UlewgjAZOPttwyMokouCvrKSZptcDXbRLOk){eval(" ascii
    $s16 = "function VwBjU(btLADsOiNPd,mGAnqUHpNkjik,ImYjzYgC){KDEn=parseInt(btLADsOiNPd,mGAnqUHpNkjik);saOsn=KDEn.toString(ImYjzYgC);return" ascii
    $s17 = "function hiimSqzGRbz(IZMQubdt,cQZXqg){return IZMQubdt.split(cQZXqg)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}