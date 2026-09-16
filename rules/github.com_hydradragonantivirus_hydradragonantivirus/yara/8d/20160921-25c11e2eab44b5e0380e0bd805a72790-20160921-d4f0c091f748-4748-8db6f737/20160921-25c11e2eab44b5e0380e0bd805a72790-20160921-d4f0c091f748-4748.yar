rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_d4f0c091f748_4748 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_d4f0c091f748680e400a49909c223265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"

  strings:
    $s1 = ";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f00" ascii
    $s2 = "urn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"KXg\";})()," ascii
    $s3 = "n f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"" ascii
    $s4 = "on f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = "){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Rh\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}