rule TTP_XOR_QUAD_CurrentVersionRun_1e31 {
  strings:
    $key_1e31 = { 4d 5e [2] 69 50 [2] 42 7c [2] 6c 5e [2] 78 45 [2] 77 5f [2] 69 42 [2] 6b 43 [2] 70 45 [2] 6c 42 [2] 70 6d }

  condition:
    any of them
}