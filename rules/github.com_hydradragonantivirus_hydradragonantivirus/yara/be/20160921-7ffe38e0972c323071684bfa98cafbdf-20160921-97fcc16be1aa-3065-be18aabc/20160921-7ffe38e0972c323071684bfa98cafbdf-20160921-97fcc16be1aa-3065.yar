rule _20160921_7ffe38e0972c323071684bfa98cafbdf_20160921_97fcc16be1aa_3065 {
  meta:
    description = "datamaliciousorder - from files 20160921_7ffe38e0972c323071684bfa98cafbdf.js, 20160921_97fcc16be1aae58b311e71df667be641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"
    hash2       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"

  strings:
    $s1 = "(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000" ascii
    $s2 = "\"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(func" ascii
    $s3 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f0" ascii
    $s4 = "n\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Lo\";})(),(function" ascii
    $s5 = "){return \"BQb\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";" ascii
    $s6 = "(){return \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";}" ascii
    $s7 = " f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"V" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}