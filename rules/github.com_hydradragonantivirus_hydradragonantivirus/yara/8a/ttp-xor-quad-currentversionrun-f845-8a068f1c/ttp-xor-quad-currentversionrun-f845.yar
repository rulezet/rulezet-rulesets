rule TTP_XOR_QUAD_CurrentVersionRun_f845 {
  strings:
    $key_f845 = { ab 2a [2] 8f 24 [2] a4 08 [2] 8a 2a [2] 9e 31 [2] 91 2b [2] 8f 36 [2] 8d 37 [2] 96 31 [2] 8a 36 [2] 96 19 }

  condition:
    any of them
}