rule TTP_XOR_QUAD_CurrentVersionRun_5019 {
  strings:
    $key_5019 = { 03 76 [2] 27 78 [2] 0c 54 [2] 22 76 [2] 36 6d [2] 39 77 [2] 27 6a [2] 25 6b [2] 3e 6d [2] 22 6a [2] 3e 45 }

  condition:
    any of them
}