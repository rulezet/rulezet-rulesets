rule TTP_XOR_QUAD_CurrentVersionRun_1b45 {
  strings:
    $key_1b45 = { 48 2a [2] 6c 24 [2] 47 08 [2] 69 2a [2] 7d 31 [2] 72 2b [2] 6c 36 [2] 6e 37 [2] 75 31 [2] 69 36 [2] 75 19 }

  condition:
    any of them
}