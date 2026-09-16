rule TTP_XOR_QUAD_CurrentVersionRun_e35a {
  strings:
    $key_e35a = { b0 35 [2] 94 3b [2] bf 17 [2] 91 35 [2] 85 2e [2] 8a 34 [2] 94 29 [2] 96 28 [2] 8d 2e [2] 91 29 [2] 8d 06 }

  condition:
    any of them
}