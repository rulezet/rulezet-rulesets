rule TTP_XOR_QUAD_CurrentVersionRun_e845 {
  strings:
    $key_e845 = { bb 2a [2] 9f 24 [2] b4 08 [2] 9a 2a [2] 8e 31 [2] 81 2b [2] 9f 36 [2] 9d 37 [2] 86 31 [2] 9a 36 [2] 86 19 }

  condition:
    any of them
}