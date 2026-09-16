rule _20160921_6ad2178e7d047e60c71f9fe1ca457b74_20160921_acebc8ac4559_3874 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash2       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"
    hash3       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s2 = "n \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(func" ascii
    $s3 = "rn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(fu" ascii
    $s4 = "t\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s5 = "urn \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(fu" ascii
    $s6 = "){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}