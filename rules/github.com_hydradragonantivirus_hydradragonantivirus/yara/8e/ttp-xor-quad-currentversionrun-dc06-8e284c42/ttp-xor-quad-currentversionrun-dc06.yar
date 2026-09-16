rule TTP_XOR_QUAD_CurrentVersionRun_dc06 {
  strings:
    $key_dc06 = { 8f 69 [2] ab 67 [2] 80 4b [2] ae 69 [2] ba 72 [2] b5 68 [2] ab 75 [2] a9 74 [2] b2 72 [2] ae 75 [2] b2 5a }

  condition:
    any of them
}