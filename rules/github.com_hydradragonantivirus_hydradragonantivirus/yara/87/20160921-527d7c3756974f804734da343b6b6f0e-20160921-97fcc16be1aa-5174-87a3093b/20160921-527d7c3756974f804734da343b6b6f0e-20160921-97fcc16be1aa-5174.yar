rule _20160921_527d7c3756974f804734da343b6b6f0e_20160921_97fcc16be1aa_5174 {
  meta:
    description = "datamaliciousorder - from files 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160921_97fcc16be1aae58b311e71df667be641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash2       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"

  strings:
    $s1 = "ion f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii
    $s2 = "eturn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})()," ascii
    $s3 = "turn \"Yv\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s4 = "Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s5 = "tion f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}