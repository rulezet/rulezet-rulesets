rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_7a3c07ee9b5a_3376 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"

  strings:
    $s1 = "return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})" ascii
    $s2 = "ction f000(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Um\";})(),(function f000(){return" ascii
    $s3 = "return \"Nv\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(" ascii
    $s4 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"HJ" ascii
    $s5 = "(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Km\";})(),(function f000(" ascii
    $s6 = "rn \"MDb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}