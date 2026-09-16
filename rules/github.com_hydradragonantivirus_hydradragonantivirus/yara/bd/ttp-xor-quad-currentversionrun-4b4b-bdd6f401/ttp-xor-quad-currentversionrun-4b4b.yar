rule TTP_XOR_QUAD_CurrentVersionRun_4b4b {
  strings:
    $key_4b4b = { 18 24 [2] 3c 2a [2] 17 06 [2] 39 24 [2] 2d 3f [2] 22 25 [2] 3c 38 [2] 3e 39 [2] 25 3f [2] 39 38 [2] 25 17 }

  condition:
    any of them
}