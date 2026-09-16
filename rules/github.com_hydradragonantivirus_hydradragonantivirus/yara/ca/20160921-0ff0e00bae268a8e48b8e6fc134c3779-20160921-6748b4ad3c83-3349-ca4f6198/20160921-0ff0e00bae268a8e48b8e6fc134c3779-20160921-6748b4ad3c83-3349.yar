rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_6748b4ad3c83_3349 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"

  strings:
    $s1 = "return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"DIa\";})()" ascii
    $s2 = "ction f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return" ascii
    $s3 = "0(){return \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\"" ascii
    $s4 = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"NYh\";})(),(functio" ascii
    $s5 = "nction f000(){return \"Sq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s6 = "(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYs\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}