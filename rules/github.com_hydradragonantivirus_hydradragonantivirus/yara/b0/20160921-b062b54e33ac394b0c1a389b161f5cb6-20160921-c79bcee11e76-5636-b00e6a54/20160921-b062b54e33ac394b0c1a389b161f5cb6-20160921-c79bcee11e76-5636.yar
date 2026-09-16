rule _20160921_b062b54e33ac394b0c1a389b161f5cb6_20160921_c79bcee11e76_5636 {
  meta:
    description = "datamaliciousorder - from files 20160921_b062b54e33ac394b0c1a389b161f5cb6.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"
    hash2       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1 = "rn \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(f" ascii
    $s2 = "ction f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){retu" ascii
    $s3 = "ction f000(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s4 = "turn \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})()," ascii
    $s5 = "){return \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}