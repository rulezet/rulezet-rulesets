rule sig_20151217_2a42f80c442dd1dabc3826f8468b659f {
  meta:
    description = "datamaliciousorder - file 20151217_2a42f80c442dd1dabc3826f8468b659f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b0c206b2b4ad7eecdc99699cfd1f28447c8fef81511a55c8b2a69df6dfd4dc6"

  strings:
    $s1  = "(Math.cos(95), 2) - 1)));} deRxarZBD[naWhAFUKIVz]++;}naWhAFUKIVz++;} return sijGUszbVHp}" fullword ascii
    $s2  = ") - 1));while(true){if (naWhAFUKIVz >= (4679+493)/862){break;}deRxarZBD[naWhAFUKIVz]=Math.round((Math.pow(Math.sin(772), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(772), 2) - 1)); while(true) { if(deRxarZBD[naWhAFUKIVz] > yNfsD[naWhAFUKIVz].length-(32+587)/619) { break; } if " ascii
    $s4  = "function NkBypqNJpdOocCEXL(yNfsD){sijGUszbVHp= '';naWhAFUKIVz=Math.round((Math.pow(Math.sin(471), 2) + Math.pow(Math.cos(471), 2" ascii
    $s5  = "function NkBypqNJpdOocCEXL(yNfsD){sijGUszbVHp= '';naWhAFUKIVz=Math.round((Math.pow(Math.sin(471), 2) + Math.pow(Math.cos(471), 2" ascii
    $s6  = "function HgoZFie(XPNEPDUYWRRRvdEKaVbjzinIgmlZuazdKLtK) {return !pcpacsDqrxG(VmMgwZnHnJGqsLz(XPNEPDUYWRRRvdEKaVbjzinIgmlZuazdKLtK" ascii
    $s7  = "function HDUQvwrrfNqclKZ(XOLSzAnbIfIlmyVzB,BbIivawHsnldcIOwpMMdVXdEOJJgUBfBzQ,uBjafxoZQxaRgCAfEYeRVUQdErlvNAntPgF){eval(XOLSzAnb" ascii
    $s8  = "function HDUQvwrrfNqclKZ(XOLSzAnbIfIlmyVzB,BbIivawHsnldcIOwpMMdVXdEOJJgUBfBzQ,uBjafxoZQxaRgCAfEYeRVUQdErlvNAntPgF){eval(XOLSzAnb" ascii
    $s9  = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s10 = "function ArUGbaFTZHha(iBfFhmILdhhjd) {return isFinite(iBfFhmILdhhjd);}" fullword ascii
    $s11 = "function VmMgwZnHnJGqsLz(CgXFTYRiDkIcJvZSsEY) {return parseFloat(CgXFTYRiDkIcJvZSsEY);}" fullword ascii
    $s12 = "function hTjDfIgrFkmABGbwX(YvylfGAovO,eVTKqBqBij) {return parseInt(YvylfGAovO,eVTKqBqBij);}" fullword ascii
    $s13 = "function dDjUm(BPrEGWYNBBi,SdyNgvdnPowFI,jfqvkFNl){VycT=hTjDfIgrFkmABGbwX(BPrEGWYNBBi,SdyNgvdnPowFI);mKCLh=VycT.toString(jfqvkFN" ascii
    $s14 = "function zWeKJdALeOwYtyXHEcSAtgBGTDWPqEkfQkYMZcDgOyNvNiARpuKdIq(HZlaeGySUcprV,bcOAeMrHprtnBF){ return NzyUGaH[IOhRoiHd[dDjUm(HZl" ascii
    $s15 = "l);return mKCLh;}" fullword ascii
    $s16 = "function HgoZFie(XPNEPDUYWRRRvdEKaVbjzinIgmlZuazdKLtK) {return !pcpacsDqrxG(VmMgwZnHnJGqsLz(XPNEPDUYWRRRvdEKaVbjzinIgmlZuazdKLtK" ascii
    $s17 = "function zWeKJdALeOwYtyXHEcSAtgBGTDWPqEkfQkYMZcDgOyNvNiARpuKdIq(HZlaeGySUcprV,bcOAeMrHprtnBF){ return NzyUGaH[IOhRoiHd[dDjUm(HZl" ascii
    $s18 = "function dDjUm(BPrEGWYNBBi,SdyNgvdnPowFI,jfqvkFNl){VycT=hTjDfIgrFkmABGbwX(BPrEGWYNBBi,SdyNgvdnPowFI);mKCLh=VycT.toString(jfqvkFN" ascii
    $s19 = "function pcpacsDqrxG(aNaHUzLRiCexsh) {return isNaN(aNaHUzLRiCexsh);}" fullword ascii
    $s20 = "function g(GLMPzvuJKTcl,xLMEkXUYRBiklA){GLMPzvuJKTcl.push(xLMEkXUYRBiklA);}" fullword ascii

  condition:
    uint16(0) == 0x4f49 and
    8 of them
}