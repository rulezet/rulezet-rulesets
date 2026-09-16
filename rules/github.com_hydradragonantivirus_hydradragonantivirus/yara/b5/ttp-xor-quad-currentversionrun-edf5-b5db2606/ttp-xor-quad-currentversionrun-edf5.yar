rule TTP_XOR_QUAD_CurrentVersionRun_edf5 {
  strings:
    $key_edf5 = { be 9a [2] 9a 94 [2] b1 b8 [2] 9f 9a [2] 8b 81 [2] 84 9b [2] 9a 86 [2] 98 87 [2] 83 81 [2] 9f 86 [2] 83 a9 }

  condition:
    any of them
}