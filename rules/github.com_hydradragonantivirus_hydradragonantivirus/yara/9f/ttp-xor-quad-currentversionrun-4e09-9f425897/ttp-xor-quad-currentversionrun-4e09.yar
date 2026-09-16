rule TTP_XOR_QUAD_CurrentVersionRun_4e09 {
  strings:
    $key_4e09 = { 1d 66 [2] 39 68 [2] 12 44 [2] 3c 66 [2] 28 7d [2] 27 67 [2] 39 7a [2] 3b 7b [2] 20 7d [2] 3c 7a [2] 20 55 }

  condition:
    any of them
}