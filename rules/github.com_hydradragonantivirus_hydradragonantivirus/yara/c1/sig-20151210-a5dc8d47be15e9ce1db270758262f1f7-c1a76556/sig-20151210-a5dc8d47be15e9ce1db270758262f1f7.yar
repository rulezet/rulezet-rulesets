rule sig_20151210_a5dc8d47be15e9ce1db270758262f1f7 {
  meta:
    description = "datamaliciousorder - file 20151210_a5dc8d47be15e9ce1db270758262f1f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7ef93b3f5e9cf77ba5107d4e05034738db3f77b81b7fadda24b7f6c919fb3f"

  strings:
    $s1  = "function JUhOghb(dOlCgkDGSiFTHCpYQyHyjtrXotGiWvTiUcrz) {return !isNaN(parseFloat(dOlCgkDGSiFTHCpYQyHyjtrXotGiWvTiUcrz)) && isFin" ascii
    $s2  = "function JUhOghb(dOlCgkDGSiFTHCpYQyHyjtrXotGiWvTiUcrz) {return !isNaN(parseFloat(dOlCgkDGSiFTHCpYQyHyjtrXotGiWvTiUcrz)) && isFin" ascii
    $s3  = "function PnWiGPOBsUtaDiayK(DnBVW){XYJpTSeiGEw= '';for(PnGhJXbRnNz=(-555+555)/975; PnGhJXbRnNz < (1639+245)/942; PnGhJXbRnNz++) {" ascii
    $s4  = "function tCmjqhsLbERHAfesjnwUYFiQntigbfVNrjqtPMKSHCxzKpqszSXkvG(xEiHWiZXqTWLE,WFxJGGmEwpqMub){ return zKvjRNLQUjjOZ[xfrKs(xEiHWi" ascii
    $s5  = "+;}} return XYJpTSeiGEw}" fullword ascii
    $s6  = "function xfrKs(hrzibMMUFfC,imoLsrpAqYyzv,NuQOyljR){zwQW=parseInt(hrzibMMUFfC,imoLsrpAqYyzv);SjBgM=zwQW.toString(NuQOyljR);return" ascii
    $s7  = "function PnWiGPOBsUtaDiayK(DnBVW){XYJpTSeiGEw= '';for(PnGhJXbRnNz=(-555+555)/975; PnGhJXbRnNz < (1639+245)/942; PnGhJXbRnNz++) {" ascii
    $s8  = "function xfrKs(hrzibMMUFfC,imoLsrpAqYyzv,NuQOyljR){zwQW=parseInt(hrzibMMUFfC,imoLsrpAqYyzv);SjBgM=zwQW.toString(NuQOyljR);return" ascii
    $s9  = "function ZNTeUSkqCoL(bRIngKqP,KtrifR){return bRIngKqP.split(KtrifR)}" fullword ascii
    $s10 = "aglfbmv=(-975+975)/753;while(true){if(aglfbmv>=(83705+903)/661){break;}zKvjRNLQUjjOZ[aglfbmv]=String.fromCharCode(aglfbmv);aglfb" ascii
    $s11 = "aglfbmv=(-975+975)/753;while(true){if(aglfbmv>=(83705+903)/661){break;}zKvjRNLQUjjOZ[aglfbmv]=String.fromCharCode(aglfbmv);aglfb" ascii
    $s12 = " SjBgM;}function ugGdcfWjVNKDBCG(KkLdsAIvusgEbawRQ){eval(KkLdsAIvusgEbawRQ)}" fullword ascii
    $s13 = "function tCmjqhsLbERHAfesjnwUYFiQntigbfVNrjqtPMKSHCxzKpqszSXkvG(xEiHWiZXqTWLE,WFxJGGmEwpqMub){ return zKvjRNLQUjjOZ[xfrKs(xEiHWi" ascii
    $s14 = "QZJuCBmJA[PnGhJXbRnNz]=(-125+125)/790; while(true) { if(QZJuCBmJA[PnGhJXbRnNz] > DnBVW[PnGhJXbRnNz].length-(504+6)/510) { break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}