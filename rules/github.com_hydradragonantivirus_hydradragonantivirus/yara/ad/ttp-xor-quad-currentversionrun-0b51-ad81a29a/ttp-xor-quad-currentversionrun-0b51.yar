rule TTP_XOR_QUAD_CurrentVersionRun_0b51 {
  strings:
    $key_0b51 = { 58 3e [2] 7c 30 [2] 57 1c [2] 79 3e [2] 6d 25 [2] 62 3f [2] 7c 22 [2] 7e 23 [2] 65 25 [2] 79 22 [2] 65 0d }

  condition:
    any of them
}