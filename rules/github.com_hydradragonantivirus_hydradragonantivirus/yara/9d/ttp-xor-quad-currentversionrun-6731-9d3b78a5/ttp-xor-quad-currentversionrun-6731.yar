rule TTP_XOR_QUAD_CurrentVersionRun_6731 {
  strings:
    $key_6731 = { 34 5e [2] 10 50 [2] 3b 7c [2] 15 5e [2] 01 45 [2] 0e 5f [2] 10 42 [2] 12 43 [2] 09 45 [2] 15 42 [2] 09 6d }

  condition:
    any of them
}