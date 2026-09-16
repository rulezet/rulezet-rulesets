rule TTP_XOR_QUAD_CurrentVersionRun_0330 {
  strings:
    $key_0330 = { 50 5f [2] 74 51 [2] 5f 7d [2] 71 5f [2] 65 44 [2] 6a 5e [2] 74 43 [2] 76 42 [2] 6d 44 [2] 71 43 [2] 6d 6c }

  condition:
    any of them
}