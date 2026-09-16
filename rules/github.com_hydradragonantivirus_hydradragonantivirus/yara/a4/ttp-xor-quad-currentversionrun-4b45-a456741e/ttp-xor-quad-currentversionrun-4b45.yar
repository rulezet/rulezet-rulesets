rule TTP_XOR_QUAD_CurrentVersionRun_4b45 {
  strings:
    $key_4b45 = { 18 2a [2] 3c 24 [2] 17 08 [2] 39 2a [2] 2d 31 [2] 22 2b [2] 3c 36 [2] 3e 37 [2] 25 31 [2] 39 36 [2] 25 19 }

  condition:
    any of them
}