rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_92203c861b27_1848 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash3       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"

  strings:
    $s1  = "000(){return \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn" ascii
    $s2  = "n \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(fu" ascii
    $s3  = "),(function f000(){return \"Tb\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})(),(function f000()" ascii
    $s4  = "0(){return \"Tb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";" ascii
    $s5  = ",(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s6  = "eturn \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})()," ascii
    $s7  = "000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu" ascii
    $s8  = "nction f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){retu" ascii
    $s9  = "(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Yz\";}" ascii
    $s10 = " \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mt\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}