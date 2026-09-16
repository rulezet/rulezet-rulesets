rule TTP_XOR_QUAD_CurrentVersionRun_7b31 {
  strings:
    $key_7b31 = { 28 5e [2] 0c 50 [2] 27 7c [2] 09 5e [2] 1d 45 [2] 12 5f [2] 0c 42 [2] 0e 43 [2] 15 45 [2] 09 42 [2] 15 6d }

  condition:
    any of them
}