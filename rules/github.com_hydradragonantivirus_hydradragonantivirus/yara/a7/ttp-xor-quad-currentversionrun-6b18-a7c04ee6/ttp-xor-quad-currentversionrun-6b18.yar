rule TTP_XOR_QUAD_CurrentVersionRun_6b18 {
  strings:
    $key_6b18 = { 38 77 [2] 1c 79 [2] 37 55 [2] 19 77 [2] 0d 6c [2] 02 76 [2] 1c 6b [2] 1e 6a [2] 05 6c [2] 19 6b [2] 05 44 }

  condition:
    any of them
}