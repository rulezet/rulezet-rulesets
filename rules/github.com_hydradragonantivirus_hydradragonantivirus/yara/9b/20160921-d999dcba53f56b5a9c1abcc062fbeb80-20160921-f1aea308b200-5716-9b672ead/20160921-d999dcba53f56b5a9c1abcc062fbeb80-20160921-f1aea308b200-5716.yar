rule _20160921_d999dcba53f56b5a9c1abcc062fbeb80_20160921_f1aea308b200_5716 {
  meta:
    description = "datamaliciousorder - from files 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash2       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1 = "})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s2 = "000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\"" ascii
    $s3 = "turn \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s4 = "){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})" ascii
    $s5 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}