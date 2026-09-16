rule TTP_XOR_QUAD_CurrentVersionRun_6b25 {
  strings:
    $key_6b25 = { 38 4a [2] 1c 44 [2] 37 68 [2] 19 4a [2] 0d 51 [2] 02 4b [2] 1c 56 [2] 1e 57 [2] 05 51 [2] 19 56 [2] 05 79 }

  condition:
    any of them
}