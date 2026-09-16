rule _20160921_1b3a88384cf704def4ce92e01728a1df_20160921_649e29a058d1_4590 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b3a88384cf704def4ce92e01728a1df.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"
    hash2       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"

  strings:
    $s1 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(f" ascii
    $s2 = "urn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(f" ascii
    $s3 = "(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(){" ascii
    $s4 = "return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})()" ascii
    $s5 = "urn \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZIi\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}