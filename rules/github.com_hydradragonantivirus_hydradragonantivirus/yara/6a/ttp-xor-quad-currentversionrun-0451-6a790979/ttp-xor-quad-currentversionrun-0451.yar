rule TTP_XOR_QUAD_CurrentVersionRun_0451 {
  strings:
    $key_0451 = { 57 3e [2] 73 30 [2] 58 1c [2] 76 3e [2] 62 25 [2] 6d 3f [2] 73 22 [2] 71 23 [2] 6a 25 [2] 76 22 [2] 6a 0d }

  condition:
    any of them
}