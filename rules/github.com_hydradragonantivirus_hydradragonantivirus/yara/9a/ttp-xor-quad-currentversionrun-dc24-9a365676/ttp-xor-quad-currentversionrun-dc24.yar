rule TTP_XOR_QUAD_CurrentVersionRun_dc24 {
  strings:
    $key_dc24 = { 8f 4b [2] ab 45 [2] 80 69 [2] ae 4b [2] ba 50 [2] b5 4a [2] ab 57 [2] a9 56 [2] b2 50 [2] ae 57 [2] b2 78 }

  condition:
    any of them
}