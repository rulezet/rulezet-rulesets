rule TTP_XOR_QUAD_CurrentVersionRun_edf4 {
  strings:
    $key_edf4 = { be 9b [2] 9a 95 [2] b1 b9 [2] 9f 9b [2] 8b 80 [2] 84 9a [2] 9a 87 [2] 98 86 [2] 83 80 [2] 9f 87 [2] 83 a8 }

  condition:
    any of them
}