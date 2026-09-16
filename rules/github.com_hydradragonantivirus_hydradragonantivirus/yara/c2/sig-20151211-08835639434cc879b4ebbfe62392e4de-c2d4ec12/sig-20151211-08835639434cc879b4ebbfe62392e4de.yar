rule sig_20151211_08835639434cc879b4ebbfe62392e4de {
  meta:
    description = "datamaliciousorder - file 20151211_08835639434cc879b4ebbfe62392e4de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a562417874c56ff768c405fecb2ab759aad8410c67963c1d910f08ee8ba27de4"

  strings:
    $s1  = "function YgWlW(jsCoRQQGtiC,DUHEMHWwiWNrt,lLoXoXsK){wJmG=parseInt(jsCoRQQGtiC,DUHEMHWwiWNrt);clivV=wJmG.toString(lLoXoXsK);return" ascii
    $s2  = " clivV;}function yGNTwBBcFClhRFq(TxEYEytwWGUvhBXfq){eval(TxEYEytwWGUvhBXfq)}" fullword ascii
    $s3  = "function vQdGkUk(qUBWgFZQgZJTUbcqUdvHLiLaLwujrrTHuLvE) {return !isNaN(parseFloat(qUBWgFZQgZJTUbcqUdvHLiLaLwujrrTHuLvE)) && isFin" ascii
    $s4  = "function vQdGkUk(qUBWgFZQgZJTUbcqUdvHLiLaLwujrrTHuLvE) {return !isNaN(parseFloat(qUBWgFZQgZJTUbcqUdvHLiLaLwujrrTHuLvE)) && isFin" ascii
    $s5  = "NEVSQEOZt[pqRyrnxkXXN]=(-683+683)/155; while(true) { if(NEVSQEOZt[pqRyrnxkXXN] > wQBtV[pqRyrnxkXXN].length-(-410+540)/130) { bre" ascii
    $s6  = "var Z=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"44\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function KqindNTNTTZJEksmDdYqpHHvoxcwlzILnDSrdWASUMxjVQnoNxtNGR(zHZBpfQKUijcY,KTePUaKpkbNUTt){ return QTVLi[YgWlW(zHZBpfQKUijcY[" ascii
    $s8  = "function rVlRWXOMFuC(tGIMUeXI,TaPisq){return tGIMUeXI.split(TaPisq)}" fullword ascii
    $s9  = "var Z=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"44\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = "var h=new Array(\"28\",\"2b\",\"26\",\"26\",\"26\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s11 = "function KqindNTNTTZJEksmDdYqpHHvoxcwlzILnDSrdWASUMxjVQnoNxtNGR(zHZBpfQKUijcY,KTePUaKpkbNUTt){ return QTVLi[YgWlW(zHZBpfQKUijcY[" ascii
    $s12 = "N]++;}pqRyrnxkXXN++;} return xPEjCUhCSrc}" fullword ascii
    $s13 = "function lhiGkpAOtWAOfDYWm(wQBtV){xPEjCUhCSrc= '';pqRyrnxkXXN=(-474+474)/424; while(true){if(pqRyrnxkXXN >= (1298+54)/676)break;" ascii
    $s14 = "function YgWlW(jsCoRQQGtiC,DUHEMHWwiWNrt,lLoXoXsK){wJmG=parseInt(jsCoRQQGtiC,DUHEMHWwiWNrt);clivV=wJmG.toString(lLoXoXsK);return" ascii
    $s15 = "var h=new Array(\"28\",\"2b\",\"26\",\"26\",\"26\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s16 = "function lhiGkpAOtWAOfDYWm(wQBtV){xPEjCUhCSrc= '';pqRyrnxkXXN=(-474+474)/424; while(true){if(pqRyrnxkXXN >= (1298+54)/676)break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}