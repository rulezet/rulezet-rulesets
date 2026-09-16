rule TTP_XOR_QUAD_CurrentVersionRun_7def {
  strings:
    $key_7def = { 2e 80 [2] 0a 8e [2] 21 a2 [2] 0f 80 [2] 1b 9b [2] 14 81 [2] 0a 9c [2] 08 9d [2] 13 9b [2] 0f 9c [2] 13 b3 }

  condition:
    any of them
}