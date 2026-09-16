rule _20160921_02b826231ece268e91633311d2c70554_20160922_edfdc00dbdbb_2605 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1 = "\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f0" ascii
    $s2 = "function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){re" ascii
    $s3 = "(){return \"WIj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";}" ascii
    $s4 = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DNa\";" ascii
    $s5 = "\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s6 = ",(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){" ascii
    $s7 = "nction f000(){return \"Nx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"DNa\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}