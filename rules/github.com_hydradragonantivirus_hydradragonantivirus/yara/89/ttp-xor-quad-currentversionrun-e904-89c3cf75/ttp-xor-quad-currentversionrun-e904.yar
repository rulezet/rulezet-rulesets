rule TTP_XOR_QUAD_CurrentVersionRun_e904 {
  strings:
    $key_e904 = { ba 6b [2] 9e 65 [2] b5 49 [2] 9b 6b [2] 8f 70 [2] 80 6a [2] 9e 77 [2] 9c 76 [2] 87 70 [2] 9b 77 [2] 87 58 }

  condition:
    any of them
}