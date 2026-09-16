rule TTP_XOR_QUAD_CurrentVersionRun_0623 {
  strings:
    $key_0623 = { 55 4c [2] 71 42 [2] 5a 6e [2] 74 4c [2] 60 57 [2] 6f 4d [2] 71 50 [2] 73 51 [2] 68 57 [2] 74 50 [2] 68 7f }

  condition:
    any of them
}