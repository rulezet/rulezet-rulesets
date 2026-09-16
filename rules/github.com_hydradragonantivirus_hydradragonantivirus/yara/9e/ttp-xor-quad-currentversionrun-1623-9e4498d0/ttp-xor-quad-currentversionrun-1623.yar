rule TTP_XOR_QUAD_CurrentVersionRun_1623 {
  strings:
    $key_1623 = { 45 4c [2] 61 42 [2] 4a 6e [2] 64 4c [2] 70 57 [2] 7f 4d [2] 61 50 [2] 63 51 [2] 78 57 [2] 64 50 [2] 78 7f }

  condition:
    any of them
}