rule _20160921_331df381948e6d95c6a9496aeda63d16_20160921_4357cd536e8c_3612 {
  meta:
    description = "datamaliciousorder - from files 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash2       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash3       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash4       = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"

  strings:
    $s1 = "Dg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function" ascii
    $s2 = " f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"" ascii
    $s3 = "(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s4 = "f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Q" ascii
    $s5 = "n \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(fu" ascii
    $s6 = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}