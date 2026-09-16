rule _20160921_202394e6610dfa0f27f737c781d5c579_20160921_97fcc16be1aa_4650 {
  meta:
    description = "datamaliciousorder - from files 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_97fcc16be1aae58b311e71df667be641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash2       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"

  strings:
    $s1 = "){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";}" ascii
    $s2 = "nction f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s3 = "unction f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s4 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s5 = "00(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}