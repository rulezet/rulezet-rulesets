rule TTP_XOR_QUAD_CurrentVersionRun_35ef {
  strings:
    $key_35ef = { 66 80 [2] 42 8e [2] 69 a2 [2] 47 80 [2] 53 9b [2] 5c 81 [2] 42 9c [2] 40 9d [2] 5b 9b [2] 47 9c [2] 5b b3 }

  condition:
    any of them
}