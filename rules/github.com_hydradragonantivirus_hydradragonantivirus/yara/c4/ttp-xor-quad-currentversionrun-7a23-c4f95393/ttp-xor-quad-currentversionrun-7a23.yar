rule TTP_XOR_QUAD_CurrentVersionRun_7a23 {
  strings:
    $key_7a23 = { 29 4c [2] 0d 42 [2] 26 6e [2] 08 4c [2] 1c 57 [2] 13 4d [2] 0d 50 [2] 0f 51 [2] 14 57 [2] 08 50 [2] 14 7f }

  condition:
    any of them
}