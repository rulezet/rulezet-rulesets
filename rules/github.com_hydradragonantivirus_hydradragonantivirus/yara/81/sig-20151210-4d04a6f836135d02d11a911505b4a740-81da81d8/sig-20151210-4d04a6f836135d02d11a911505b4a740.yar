rule sig_20151210_4d04a6f836135d02d11a911505b4a740 {
  meta:
    description = "datamaliciousorder - file 20151210_4d04a6f836135d02d11a911505b4a740.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d326d90b145b55a0466fbb5213e3105afa621a523569b6b8dd1034a74cfc22cb"

  strings:
    $s1  = "function VVMVfYd(fTaVljZzWefhhNxkLgVLidHsZnLYhHYiYQRb) {return !isNaN(parseFloat(fTaVljZzWefhhNxkLgVLidHsZnLYhHYiYQRb)) && isFin" ascii
    $s2  = "function VVMVfYd(fTaVljZzWefhhNxkLgVLidHsZnLYhHYiYQRb) {return !isNaN(parseFloat(fTaVljZzWefhhNxkLgVLidHsZnLYhHYiYQRb)) && isFin" ascii
    $s3  = "function IABBYOasKaryGbfBbybTEODLyYFvqpmKuyDvqfdYVadIkzezmwJZhe(qaVCZOKMYBHZG,PPmFqoCeJqyPbL){ return GEzJMDUBYebys[HeMCF(qaVCZO" ascii
    $s4  = "function HeMCF(JSeaMrjwiLw,iUilTXxRElzjY,heNqLRpR){MaCm=parseInt(JSeaMrjwiLw,iUilTXxRElzjY);XYiqL=MaCm.toString(heNqLRpR);return" ascii
    $s5  = "function IABBYOasKaryGbfBbybTEODLyYFvqpmKuyDvqfdYVadIkzezmwJZhe(qaVCZOKMYBHZG,PPmFqoCeJqyPbL){ return GEzJMDUBYebys[HeMCF(qaVCZO" ascii
    $s6  = "dcKjDQx=(-269+269)/594;while(true){if(dcKjDQx>=(20224+896)/165){break;}GEzJMDUBYebys[dcKjDQx]=String.fromCharCode(dcKjDQx);dcKjD" ascii
    $s7  = "function YIKcdvcCtHSKGIvRY(NlGOR){crZztWDNzNV= '';for(PGRtLVNcYni=(-159+159)/442; PGRtLVNcYni < (383+821)/602; PGRtLVNcYni++) {B" ascii
    $s8  = "dcKjDQx=(-269+269)/594;while(true){if(dcKjDQx>=(20224+896)/165){break;}GEzJMDUBYebys[dcKjDQx]=String.fromCharCode(dcKjDQx);dcKjD" ascii
    $s9  = " XYiqL;}function hZVlmLkWlweDiaB(ZjcWMdyqZvjMhpdDD){eval(ZjcWMdyqZvjMhpdDD)}" fullword ascii
    $s10 = "lQvXLJZm[PGRtLVNcYni]=(-481+481)/812; while(true) { if(BlQvXLJZm[PGRtLVNcYni] > NlGOR[PGRtLVNcYni].length-(-142+327)/185) { brea" ascii
    $s11 = "function YIKcdvcCtHSKGIvRY(NlGOR){crZztWDNzNV= '';for(PGRtLVNcYni=(-159+159)/442; PGRtLVNcYni < (383+821)/602; PGRtLVNcYni++) {B" ascii
    $s12 = ";}} return crZztWDNzNV}" fullword ascii
    $s13 = "function HeMCF(JSeaMrjwiLw,iUilTXxRElzjY,heNqLRpR){MaCm=parseInt(JSeaMrjwiLw,iUilTXxRElzjY);XYiqL=MaCm.toString(heNqLRpR);return" ascii
    $s14 = "function tLsEKPnVBJf(VEXpyLAQ,zTeXnj){return VEXpyLAQ.split(zTeXnj)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}