rule TTP_XOR_QUAD_CurrentVersionRun_6b78 {
  strings:
    $key_6b78 = { 38 17 [2] 1c 19 [2] 37 35 [2] 19 17 [2] 0d 0c [2] 02 16 [2] 1c 0b [2] 1e 0a [2] 05 0c [2] 19 0b [2] 05 24 }

  condition:
    any of them
}