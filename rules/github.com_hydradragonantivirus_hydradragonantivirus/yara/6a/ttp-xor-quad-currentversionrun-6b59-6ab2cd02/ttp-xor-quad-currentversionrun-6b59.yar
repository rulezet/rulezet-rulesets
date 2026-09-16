rule TTP_XOR_QUAD_CurrentVersionRun_6b59 {
  strings:
    $key_6b59 = { 38 36 [2] 1c 38 [2] 37 14 [2] 19 36 [2] 0d 2d [2] 02 37 [2] 1c 2a [2] 1e 2b [2] 05 2d [2] 19 2a [2] 05 05 }

  condition:
    any of them
}