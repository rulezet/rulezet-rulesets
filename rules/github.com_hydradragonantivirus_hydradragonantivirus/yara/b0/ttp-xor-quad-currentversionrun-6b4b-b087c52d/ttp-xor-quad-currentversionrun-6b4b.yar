rule TTP_XOR_QUAD_CurrentVersionRun_6b4b {
  strings:
    $key_6b4b = { 38 24 [2] 1c 2a [2] 37 06 [2] 19 24 [2] 0d 3f [2] 02 25 [2] 1c 38 [2] 1e 39 [2] 05 3f [2] 19 38 [2] 05 17 }

  condition:
    any of them
}