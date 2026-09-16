rule TTP_XOR_QUAD_CurrentVersionRun_26ef {
  strings:
    $key_26ef = { 75 80 [2] 51 8e [2] 7a a2 [2] 54 80 [2] 40 9b [2] 4f 81 [2] 51 9c [2] 53 9d [2] 48 9b [2] 54 9c [2] 48 b3 }

  condition:
    any of them
}