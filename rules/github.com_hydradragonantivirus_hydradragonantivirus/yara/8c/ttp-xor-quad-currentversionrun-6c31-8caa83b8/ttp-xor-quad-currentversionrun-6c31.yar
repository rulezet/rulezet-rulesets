rule TTP_XOR_QUAD_CurrentVersionRun_6c31 {
  strings:
    $key_6c31 = { 3f 5e [2] 1b 50 [2] 30 7c [2] 1e 5e [2] 0a 45 [2] 05 5f [2] 1b 42 [2] 19 43 [2] 02 45 [2] 1e 42 [2] 02 6d }

  condition:
    any of them
}