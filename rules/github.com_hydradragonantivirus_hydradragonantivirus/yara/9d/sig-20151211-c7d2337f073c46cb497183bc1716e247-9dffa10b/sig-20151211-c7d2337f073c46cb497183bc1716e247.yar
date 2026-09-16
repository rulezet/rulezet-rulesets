rule sig_20151211_c7d2337f073c46cb497183bc1716e247 {
  meta:
    description = "datamaliciousorder - file 20151211_c7d2337f073c46cb497183bc1716e247.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9bd6bae1db6fb590991542e54e88412d977c288309d54744f00412d278cd1ba"

  strings:
    $s1  = "function dcFvRWr(zsFdGEYKKoPfzGEfyMkZKCMAxpetzPySPScH) {return !isNaN(parseFloat(zsFdGEYKKoPfzGEfyMkZKCMAxpetzPySPScH)) && isFin" ascii
    $s2  = "function dcFvRWr(zsFdGEYKKoPfzGEfyMkZKCMAxpetzPySPScH) {return !isNaN(parseFloat(zsFdGEYKKoPfzGEfyMkZKCMAxpetzPySPScH)) && isFin" ascii
    $s3  = "function buUsBRwGjgituQVhc(xJasD){RoUIRopEvut= '';AUtQggemGRb=(-358+358)/80; while(true){if(AUtQggemGRb >= (-431+633)/101)break;" ascii
    $s4  = "function SSMnY(gNasdqEmrlw,zGrvjhHNgRnvq,ewVDDpnb){rJMm=parseInt(gNasdqEmrlw,zGrvjhHNgRnvq);zPgnS=rJMm.toString(ewVDDpnb);return" ascii
    $s5  = "function chyGMVFsZJObrFVuEoxmxrWThqZyhQOKhVhtnTCIoKdvNJyWoUMCjz(vRwWffuVZSMMg,LoqFIYKRDnZPvI){ return zIJEp[SSMnY(vRwWffuVZSMMg[" ascii
    $s6  = " zPgnS;}function OvqLqpTZFWnZGxX(GbgrpFvmJBRsnZKuR){eval(GbgrpFvmJBRsnZKuR)}" fullword ascii
    $s7  = "var L=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s8  = "var L=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5e\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = "function buUsBRwGjgituQVhc(xJasD){RoUIRopEvut= '';AUtQggemGRb=(-358+358)/80; while(true){if(AUtQggemGRb >= (-431+633)/101)break;" ascii
    $s10 = "function DbfyfInDXpl(mKOsswtB,hdwJcY){return mKOsswtB.split(hdwJcY)}" fullword ascii
    $s11 = "function SSMnY(gNasdqEmrlw,zGrvjhHNgRnvq,ewVDDpnb){rJMm=parseInt(gNasdqEmrlw,zGrvjhHNgRnvq);zPgnS=rJMm.toString(ewVDDpnb);return" ascii
    $s12 = "LWmeDyVKS[AUtQggemGRb]=(-818+818)/441; while(true) { if(LWmeDyVKS[AUtQggemGRb] > xJasD[AUtQggemGRb].length-(-560+645)/85) { brea" ascii
    $s13 = "+;}AUtQggemGRb++;} return RoUIRopEvut}" fullword ascii
    $s14 = "var P=new Array(\"2d\",\"2a\",\"2b\",\"2a\",\"2f\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s15 = "function chyGMVFsZJObrFVuEoxmxrWThqZyhQOKhVhtnTCIoKdvNJyWoUMCjz(vRwWffuVZSMMg,LoqFIYKRDnZPvI){ return zIJEp[SSMnY(vRwWffuVZSMMg[" ascii
    $s16 = "var P=new Array(\"2d\",\"2a\",\"2b\",\"2a\",\"2f\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}