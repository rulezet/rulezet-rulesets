rule TTP_XOR_QUAD_CurrentVersionRun_2d31 {
  strings:
    $key_2d31 = { 7e 5e [2] 5a 50 [2] 71 7c [2] 5f 5e [2] 4b 45 [2] 44 5f [2] 5a 42 [2] 58 43 [2] 43 45 [2] 5f 42 [2] 43 6d }

  condition:
    any of them
}