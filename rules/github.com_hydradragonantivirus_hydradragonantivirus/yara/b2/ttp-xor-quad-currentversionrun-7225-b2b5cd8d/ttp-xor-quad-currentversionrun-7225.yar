rule TTP_XOR_QUAD_CurrentVersionRun_7225 {
  strings:
    $key_7225 = { 21 4a [2] 05 44 [2] 2e 68 [2] 00 4a [2] 14 51 [2] 1b 4b [2] 05 56 [2] 07 57 [2] 1c 51 [2] 00 56 [2] 1c 79 }

  condition:
    any of them
}