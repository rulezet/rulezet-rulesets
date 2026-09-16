rule _20160921_02b826231ece268e91633311d2c70554_20160921_539bde925d7d_3183 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash3       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){re" ascii
    $s2 = "),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s3 = "f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"D" ascii
    $s4 = "tion f000(){return \"ZFe\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s5 = "{return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Mc\";})" ascii
    $s6 = "){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}