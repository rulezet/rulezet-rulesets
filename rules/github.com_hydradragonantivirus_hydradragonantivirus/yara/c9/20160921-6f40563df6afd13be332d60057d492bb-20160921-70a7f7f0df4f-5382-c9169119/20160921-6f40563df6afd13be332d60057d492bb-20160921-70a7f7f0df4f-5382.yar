rule _20160921_6f40563df6afd13be332d60057d492bb_20160921_70a7f7f0df4f_5382 {
  meta:
    description = "datamaliciousorder - from files 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash2       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash3       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash4       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"
    hash5       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1 = "ction f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return " ascii
    $s2 = "0(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\"" ascii
    $s3 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";}" ascii
    $s4 = "ction f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){retur" ascii
    $s5 = "\"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}