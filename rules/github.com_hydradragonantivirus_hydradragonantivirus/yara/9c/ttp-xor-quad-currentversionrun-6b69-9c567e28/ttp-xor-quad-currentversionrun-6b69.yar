rule TTP_XOR_QUAD_CurrentVersionRun_6b69 {
  strings:
    $key_6b69 = { 38 06 [2] 1c 08 [2] 37 24 [2] 19 06 [2] 0d 1d [2] 02 07 [2] 1c 1a [2] 1e 1b [2] 05 1d [2] 19 1a [2] 05 35 }

  condition:
    any of them
}