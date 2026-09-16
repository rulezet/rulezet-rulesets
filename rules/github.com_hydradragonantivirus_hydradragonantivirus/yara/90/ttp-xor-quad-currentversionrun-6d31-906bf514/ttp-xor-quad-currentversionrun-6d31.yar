rule TTP_XOR_QUAD_CurrentVersionRun_6d31 {
  strings:
    $key_6d31 = { 3e 5e [2] 1a 50 [2] 31 7c [2] 1f 5e [2] 0b 45 [2] 04 5f [2] 1a 42 [2] 18 43 [2] 03 45 [2] 1f 42 [2] 03 6d }

  condition:
    any of them
}