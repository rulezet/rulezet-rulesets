rule _20160921_4357cd536e8c7d04b6d87c9010da5db8_20160921_8a6f0879f250_5054 {
  meta:
    description = "datamaliciousorder - from files 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash2       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash3       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash4       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"
    hash5       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash6       = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"

  strings:
    $s1 = "(){return \"ZIi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";}" ascii
    $s2 = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000()" ascii
    $s3 = " \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s4 = " \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(fun" ascii
    $s5 = "nction f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}