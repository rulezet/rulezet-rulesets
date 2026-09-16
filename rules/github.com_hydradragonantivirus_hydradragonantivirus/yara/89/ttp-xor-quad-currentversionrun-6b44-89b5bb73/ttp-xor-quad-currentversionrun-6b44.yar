rule TTP_XOR_QUAD_CurrentVersionRun_6b44 {
  strings:
    $key_6b44 = { 38 2b [2] 1c 25 [2] 37 09 [2] 19 2b [2] 0d 30 [2] 02 2a [2] 1c 37 [2] 1e 36 [2] 05 30 [2] 19 37 [2] 05 18 }

  condition:
    any of them
}