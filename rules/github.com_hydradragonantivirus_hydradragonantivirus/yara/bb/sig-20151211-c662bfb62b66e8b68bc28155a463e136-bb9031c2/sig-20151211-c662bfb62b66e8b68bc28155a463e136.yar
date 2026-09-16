rule sig_20151211_c662bfb62b66e8b68bc28155a463e136 {
  meta:
    description = "datamaliciousorder - file 20151211_c662bfb62b66e8b68bc28155a463e136.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ca1987fde1f2694b0505908a311bd22dabe42534ff44c297cc0722bad1edf39"

  strings:
    $s1  = "function iqTyvmW(VYnSRvqKxyqJTEjcxsGyJcdcKVeGydLfdnFu) {return !isNaN(parseFloat(VYnSRvqKxyqJTEjcxsGyJcdcKVeGydLfdnFu)) && isFin" ascii
    $s2  = "function iqTyvmW(VYnSRvqKxyqJTEjcxsGyJcdcKVeGydLfdnFu) {return !isNaN(parseFloat(VYnSRvqKxyqJTEjcxsGyJcdcKVeGydLfdnFu)) && isFin" ascii
    $s3  = "function PRfHaRTjwVIjYKuPJntjFbOxoFIhgqyJPKCXlWeDuPgkUwezrHzduu(ZZvlCCxbcfDkd,PpHrpuSmvXgKhf){ return XRgUL[xavWw(ZZvlCCxbcfDkd[" ascii
    $s4  = ";}pGROUuCTIDq++;} return vCXxwApsCWj}" fullword ascii
    $s5  = " QYNpP;}function ATPIKeZjiLNZsHX(WFzCgDAykrUrNkxIA){eval(WFzCgDAykrUrNkxIA)}" fullword ascii
    $s6  = "var g=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function iOkQCKIYlAsGRCmGC(voBnb){vCXxwApsCWj= '';pGROUuCTIDq=(-501+501)/941; while(true){if(pGROUuCTIDq >= (1922+26)/974)break;" ascii
    $s8  = "function VmqavCdttqt(XeeWTOjP,swVlKS){return XeeWTOjP.split(swVlKS)}" fullword ascii
    $s9  = "var t=new Array(\"28\",\"2b\",\"29\",\"29\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s10 = "var t=new Array(\"28\",\"2b\",\"29\",\"29\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s11 = "cGkijPFBd[pGROUuCTIDq]=(-765+765)/681; while(true) { if(cGkijPFBd[pGROUuCTIDq] > voBnb[pGROUuCTIDq].length-(-775+851)/76) { brea" ascii
    $s12 = "function iOkQCKIYlAsGRCmGC(voBnb){vCXxwApsCWj= '';pGROUuCTIDq=(-501+501)/941; while(true){if(pGROUuCTIDq >= (1922+26)/974)break;" ascii
    $s13 = "var g=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "function xavWw(qksFoSlGfSR,lKUDYhMVSgAPA,EfKZTJZi){AKlk=parseInt(qksFoSlGfSR,lKUDYhMVSgAPA);QYNpP=AKlk.toString(EfKZTJZi);return" ascii
    $s15 = "function PRfHaRTjwVIjYKuPJntjFbOxoFIhgqyJPKCXlWeDuPgkUwezrHzduu(ZZvlCCxbcfDkd,PpHrpuSmvXgKhf){ return XRgUL[xavWw(ZZvlCCxbcfDkd[" ascii
    $s16 = "function xavWw(qksFoSlGfSR,lKUDYhMVSgAPA,EfKZTJZi){AKlk=parseInt(qksFoSlGfSR,lKUDYhMVSgAPA);QYNpP=AKlk.toString(EfKZTJZi);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}