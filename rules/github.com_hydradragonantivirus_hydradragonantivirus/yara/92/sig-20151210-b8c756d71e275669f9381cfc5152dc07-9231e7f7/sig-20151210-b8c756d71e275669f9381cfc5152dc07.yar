rule sig_20151210_b8c756d71e275669f9381cfc5152dc07 {
  meta:
    description = "datamaliciousorder - file 20151210_b8c756d71e275669f9381cfc5152dc07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe34358d5773b6e7fd1139e69ef8659f74265c80729d40c07f28b98cf906ba5f"

  strings:
    $s1  = "function QYnxBYU(nzfLVgLAVNUxSQEkhwhwJzxYOolgRIToKKrm) {return !isNaN(parseFloat(nzfLVgLAVNUxSQEkhwhwJzxYOolgRIToKKrm)) && isFin" ascii
    $s2  = "function QYnxBYU(nzfLVgLAVNUxSQEkhwhwJzxYOolgRIToKKrm) {return !isNaN(parseFloat(nzfLVgLAVNUxSQEkhwhwJzxYOolgRIToKKrm)) && isFin" ascii
    $s3  = " Wetkd;}function QEIPaubtncoILEE(KYzPcytYBbbXRAeee){eval(KYzPcytYBbbXRAeee)}" fullword ascii
    $s4  = "+;}} return lEsHVKhuwJQ}" fullword ascii
    $s5  = "function oFFRNuPZFkktSNRlv(KVrNw){lEsHVKhuwJQ= '';for(XzabXboJTay=(-188+188)/820; XzabXboJTay < (753+109)/431; XzabXboJTay++) {C" ascii
    $s6  = "function oFFRNuPZFkktSNRlv(KVrNw){lEsHVKhuwJQ= '';for(XzabXboJTay=(-188+188)/820; XzabXboJTay < (753+109)/431; XzabXboJTay++) {C" ascii
    $s7  = "function OmwvdwYghXdxxoAdzpXwFFilmAVJhKLsIgEvDoRSjQOuuOfByZqbii(KNnNgUzYcvccy,qUCVLRUKkUuMop){ return VebzZ[PLHLu(KNnNgUzYcvccy[" ascii
    $s8  = "function OmwvdwYghXdxxoAdzpXwFFilmAVJhKLsIgEvDoRSjQOuuOfByZqbii(KNnNgUzYcvccy,qUCVLRUKkUuMop){ return VebzZ[PLHLu(KNnNgUzYcvccy[" ascii
    $s9  = "function PLHLu(YtSgsnUzjiT,veOiVuusAtkfD,oLhiOJBF){XHhM=parseInt(YtSgsnUzjiT,veOiVuusAtkfD);Wetkd=XHhM.toString(oLhiOJBF);return" ascii
    $s10 = "function PLHLu(YtSgsnUzjiT,veOiVuusAtkfD,oLhiOJBF){XHhM=parseInt(YtSgsnUzjiT,veOiVuusAtkfD);Wetkd=XHhM.toString(oLhiOJBF);return" ascii
    $s11 = "IafqniqZ[XzabXboJTay]=(-898+898)/416; while(true) { if(CIafqniqZ[XzabXboJTay] > KVrNw[XzabXboJTay].length-(-118+884)/766) { brea" ascii
    $s12 = "function hzxGzzHMobz(ZJjjgSkS,cAxoaT){return ZJjjgSkS.split(cAxoaT)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}