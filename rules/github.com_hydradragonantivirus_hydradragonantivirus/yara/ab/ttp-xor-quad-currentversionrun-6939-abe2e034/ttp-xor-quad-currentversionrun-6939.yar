rule TTP_XOR_QUAD_CurrentVersionRun_6939 {
  strings:
    $key_6939 = { 3a 56 [2] 1e 58 [2] 35 74 [2] 1b 56 [2] 0f 4d [2] 00 57 [2] 1e 4a [2] 1c 4b [2] 07 4d [2] 1b 4a [2] 07 65 }

  condition:
    any of them
}