rule TTP_XOR_QUAD_CurrentVersionRun_dcdb {
  strings:
    $key_dcdb = { 8f b4 [2] ab ba [2] 80 96 [2] ae b4 [2] ba af [2] b5 b5 [2] ab a8 [2] a9 a9 [2] b2 af [2] ae a8 [2] b2 87 }

  condition:
    any of them
}