rule TTP_XOR_QUAD_CurrentVersionRun_3e23 {
  strings:
    $key_3e23 = { 6d 4c [2] 49 42 [2] 62 6e [2] 4c 4c [2] 58 57 [2] 57 4d [2] 49 50 [2] 4b 51 [2] 50 57 [2] 4c 50 [2] 50 7f }

  condition:
    any of them
}