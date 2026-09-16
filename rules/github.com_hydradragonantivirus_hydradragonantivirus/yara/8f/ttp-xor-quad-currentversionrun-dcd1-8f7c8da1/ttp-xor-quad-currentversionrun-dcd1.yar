rule TTP_XOR_QUAD_CurrentVersionRun_dcd1 {
  strings:
    $key_dcd1 = { 8f be [2] ab b0 [2] 80 9c [2] ae be [2] ba a5 [2] b5 bf [2] ab a2 [2] a9 a3 [2] b2 a5 [2] ae a2 [2] b2 8d }

  condition:
    any of them
}