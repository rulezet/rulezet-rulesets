rule TTP_XOR_QUAD_CurrentVersionRun_1b31 {
  strings:
    $key_1b31 = { 48 5e [2] 6c 50 [2] 47 7c [2] 69 5e [2] 7d 45 [2] 72 5f [2] 6c 42 [2] 6e 43 [2] 75 45 [2] 69 42 [2] 75 6d }

  condition:
    any of them
}