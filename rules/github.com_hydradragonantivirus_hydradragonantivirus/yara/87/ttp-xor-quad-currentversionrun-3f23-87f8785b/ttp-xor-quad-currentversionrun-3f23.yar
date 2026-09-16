rule TTP_XOR_QUAD_CurrentVersionRun_3f23 {
  strings:
    $key_3f23 = { 6c 4c [2] 48 42 [2] 63 6e [2] 4d 4c [2] 59 57 [2] 56 4d [2] 48 50 [2] 4a 51 [2] 51 57 [2] 4d 50 [2] 51 7f }

  condition:
    any of them
}