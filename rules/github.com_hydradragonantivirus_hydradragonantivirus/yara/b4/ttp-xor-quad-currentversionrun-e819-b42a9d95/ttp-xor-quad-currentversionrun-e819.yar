rule TTP_XOR_QUAD_CurrentVersionRun_e819 {
  strings:
    $key_e819 = { bb 76 [2] 9f 78 [2] b4 54 [2] 9a 76 [2] 8e 6d [2] 81 77 [2] 9f 6a [2] 9d 6b [2] 86 6d [2] 9a 6a [2] 86 45 }

  condition:
    any of them
}