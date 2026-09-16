rule TTP_XOR_QUAD_CurrentVersionRun_e728 {
  strings:
    $key_e728 = { b4 47 [2] 90 49 [2] bb 65 [2] 95 47 [2] 81 5c [2] 8e 46 [2] 90 5b [2] 92 5a [2] 89 5c [2] 95 5b [2] 89 74 }

  condition:
    any of them
}