rule _20160921_b5efb4ba3e712545d64a2d00b3dcd76e_20160921_ec2d2710e921_5648 {
  meta:
    description = "datamaliciousorder - from files 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"
    hash2       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1 = "return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})()" ascii
    $s2 = "unction fuck(){return \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){retu" ascii
    $s3 = "v\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IOs\";})(),(function " ascii
    $s4 = " \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(fun" ascii
    $s5 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}