rule TTP_XOR_QUAD_CurrentVersionRun_1423 {
  strings:
    $key_1423 = { 47 4c [2] 63 42 [2] 48 6e [2] 66 4c [2] 72 57 [2] 7d 4d [2] 63 50 [2] 61 51 [2] 7a 57 [2] 66 50 [2] 7a 7f }

  condition:
    any of them
}