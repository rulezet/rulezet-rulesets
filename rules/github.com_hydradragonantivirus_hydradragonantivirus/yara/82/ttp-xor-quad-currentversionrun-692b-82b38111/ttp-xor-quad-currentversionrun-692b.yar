rule TTP_XOR_QUAD_CurrentVersionRun_692b {
  strings:
    $key_692b = { 3a 44 [2] 1e 4a [2] 35 66 [2] 1b 44 [2] 0f 5f [2] 00 45 [2] 1e 58 [2] 1c 59 [2] 07 5f [2] 1b 58 [2] 07 77 }

  condition:
    any of them
}