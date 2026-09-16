rule _20160921_6ca29d2ebdcaa2724b801c02414faf7f_20160922_b9c8ae1e2648_5361 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash2       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1 = "\"Kw\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(funct" ascii
    $s2 = "unction f000(){return \"YTp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s3 = "f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Fs" ascii
    $s4 = "function f000(){return \"NBs\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s5 = "(function f000(){return \"Br\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MJq\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}