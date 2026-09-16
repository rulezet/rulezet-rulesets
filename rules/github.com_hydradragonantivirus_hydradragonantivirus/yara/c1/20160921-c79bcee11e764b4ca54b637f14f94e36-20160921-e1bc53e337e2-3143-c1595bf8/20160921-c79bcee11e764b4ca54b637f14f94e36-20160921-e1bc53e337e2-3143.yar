rule _20160921_c79bcee11e764b4ca54b637f14f94e36_20160921_e1bc53e337e2_3143 {
  meta:
    description = "datamaliciousorder - from files 20160921_c79bcee11e764b4ca54b637f14f94e36.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"
    hash2       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f000(){retu" ascii
    $s2 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";})(),(func" ascii
    $s3 = "on f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s4 = "urn \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(" ascii
    $s5 = "{return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})()" ascii
    $s6 = "0(){return \"Wb\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s7 = "n \"IAa\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}