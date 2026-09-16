rule TTP_XOR_QUAD_CurrentVersionRun_4def {
  strings:
    $key_4def = { 1e 80 [2] 3a 8e [2] 11 a2 [2] 3f 80 [2] 2b 9b [2] 24 81 [2] 3a 9c [2] 38 9d [2] 23 9b [2] 3f 9c [2] 23 b3 }

  condition:
    any of them
}