rule TTP_XOR_QUAD_CurrentVersionRun_e937 {
  strings:
    $key_e937 = { ba 58 [2] 9e 56 [2] b5 7a [2] 9b 58 [2] 8f 43 [2] 80 59 [2] 9e 44 [2] 9c 45 [2] 87 43 [2] 9b 44 [2] 87 6b }

  condition:
    any of them
}