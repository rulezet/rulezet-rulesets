rule TTP_XOR_QUAD_CurrentVersionRun_6b09 {
  strings:
    $key_6b09 = { 38 66 [2] 1c 68 [2] 37 44 [2] 19 66 [2] 0d 7d [2] 02 67 [2] 1c 7a [2] 1e 7b [2] 05 7d [2] 19 7a [2] 05 55 }

  condition:
    any of them
}