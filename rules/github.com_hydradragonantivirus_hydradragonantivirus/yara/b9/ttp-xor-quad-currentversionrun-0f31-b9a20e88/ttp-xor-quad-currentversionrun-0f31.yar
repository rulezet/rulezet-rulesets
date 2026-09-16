rule TTP_XOR_QUAD_CurrentVersionRun_0f31 {
  strings:
    $key_0f31 = { 5c 5e [2] 78 50 [2] 53 7c [2] 7d 5e [2] 69 45 [2] 66 5f [2] 78 42 [2] 7a 43 [2] 61 45 [2] 7d 42 [2] 61 6d }

  condition:
    any of them
}