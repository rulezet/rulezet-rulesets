rule TTP_XOR_QUAD_CurrentVersionRun_4e31 {
  strings:
    $key_4e31 = { 1d 5e [2] 39 50 [2] 12 7c [2] 3c 5e [2] 28 45 [2] 27 5f [2] 39 42 [2] 3b 43 [2] 20 45 [2] 3c 42 [2] 20 6d }

  condition:
    any of them
}