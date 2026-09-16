rule _20160921_262709d34b477380050375a3b5b2833b_20160921_4bad0ae96eb9_4752 {
  meta:
    description = "datamaliciousorder - from files 20160921_262709d34b477380050375a3b5b2833b.js, 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2738de24af2af834f5ce43b4e99137d47cd1993ec0b6dc3c1071deb99efcd62c"
    hash2       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash3       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"
    hash4       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"
    hash5       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"
    hash6       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1 = "{return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})" ascii
    $s2 = ";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(function fuck" ascii
    $s3 = "urn \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(fun" ascii
    $s4 = "ck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\"" ascii
    $s5 = "unction fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}