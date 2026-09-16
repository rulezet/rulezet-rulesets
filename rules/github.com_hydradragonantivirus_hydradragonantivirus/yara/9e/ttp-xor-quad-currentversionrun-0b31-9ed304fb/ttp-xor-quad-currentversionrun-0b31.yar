rule TTP_XOR_QUAD_CurrentVersionRun_0b31 {
  strings:
    $key_0b31 = { 58 5e [2] 7c 50 [2] 57 7c [2] 79 5e [2] 6d 45 [2] 62 5f [2] 7c 42 [2] 7e 43 [2] 65 45 [2] 79 42 [2] 65 6d }

  condition:
    any of them
}