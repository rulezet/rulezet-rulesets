rule TTP_XOR_QUAD_CurrentVersionRun_0431 {
  strings:
    $key_0431 = { 57 5e [2] 73 50 [2] 58 7c [2] 76 5e [2] 62 45 [2] 6d 5f [2] 73 42 [2] 71 43 [2] 6a 45 [2] 76 42 [2] 6a 6d }

  condition:
    any of them
}