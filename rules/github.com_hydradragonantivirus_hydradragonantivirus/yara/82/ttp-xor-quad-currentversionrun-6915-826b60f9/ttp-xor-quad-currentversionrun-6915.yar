rule TTP_XOR_QUAD_CurrentVersionRun_6915 {
  strings:
    $key_6915 = { 3a 7a [2] 1e 74 [2] 35 58 [2] 1b 7a [2] 0f 61 [2] 00 7b [2] 1e 66 [2] 1c 67 [2] 07 61 [2] 1b 66 [2] 07 49 }

  condition:
    any of them
}