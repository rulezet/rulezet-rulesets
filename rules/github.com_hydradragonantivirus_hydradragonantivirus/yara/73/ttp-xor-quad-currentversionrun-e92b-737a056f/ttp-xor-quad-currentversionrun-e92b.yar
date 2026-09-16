rule TTP_XOR_QUAD_CurrentVersionRun_e92b {
  strings:
    $key_e92b = { ba 44 [2] 9e 4a [2] b5 66 [2] 9b 44 [2] 8f 5f [2] 80 45 [2] 9e 58 [2] 9c 59 [2] 87 5f [2] 9b 58 [2] 87 77 }

  condition:
    any of them
}