rule TTP_XOR_QUAD_CurrentVersionRun_2def {
  strings:
    $key_2def = { 7e 80 [2] 5a 8e [2] 71 a2 [2] 5f 80 [2] 4b 9b [2] 44 81 [2] 5a 9c [2] 58 9d [2] 43 9b [2] 5f 9c [2] 43 b3 }

  condition:
    any of them
}