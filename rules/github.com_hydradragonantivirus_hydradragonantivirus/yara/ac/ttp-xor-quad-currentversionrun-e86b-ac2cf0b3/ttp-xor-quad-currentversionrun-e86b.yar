rule TTP_XOR_QUAD_CurrentVersionRun_e86b {
  strings:
    $key_e86b = { bb 04 [2] 9f 0a [2] b4 26 [2] 9a 04 [2] 8e 1f [2] 81 05 [2] 9f 18 [2] 9d 19 [2] 86 1f [2] 9a 18 [2] 86 37 }

  condition:
    any of them
}