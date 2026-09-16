rule _20160921_24cca85b9483630d2e2e50bdd8aa5013_20160921_4787695fef44_4741 {
  meta:
    description = "datamaliciousorder - from files 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash2       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash3       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"

  strings:
    $s1 = "n \"Wy\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s2 = " f000(){return \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"GG" ascii
    $s3 = "ction f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s4 = ";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f" ascii
    $s5 = "\"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}