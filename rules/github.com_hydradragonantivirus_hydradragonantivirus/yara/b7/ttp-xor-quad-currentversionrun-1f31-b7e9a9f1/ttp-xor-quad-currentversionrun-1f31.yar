rule TTP_XOR_QUAD_CurrentVersionRun_1f31 {
  strings:
    $key_1f31 = { 4c 5e [2] 68 50 [2] 43 7c [2] 6d 5e [2] 79 45 [2] 76 5f [2] 68 42 [2] 6a 43 [2] 71 45 [2] 6d 42 [2] 71 6d }

  condition:
    any of them
}