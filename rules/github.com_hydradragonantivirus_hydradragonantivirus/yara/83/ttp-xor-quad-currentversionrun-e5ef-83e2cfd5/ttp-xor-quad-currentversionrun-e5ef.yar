rule TTP_XOR_QUAD_CurrentVersionRun_e5ef {
  strings:
    $key_e5ef = { b6 80 [2] 92 8e [2] b9 a2 [2] 97 80 [2] 83 9b [2] 8c 81 [2] 92 9c [2] 90 9d [2] 8b 9b [2] 97 9c [2] 8b b3 }

  condition:
    any of them
}