rule TTP_XOR_QUAD_CurrentVersionRun_1431 {
  strings:
    $key_1431 = { 47 5e [2] 63 50 [2] 48 7c [2] 66 5e [2] 72 45 [2] 7d 5f [2] 63 42 [2] 61 43 [2] 7a 45 [2] 66 42 [2] 7a 6d }

  condition:
    any of them
}