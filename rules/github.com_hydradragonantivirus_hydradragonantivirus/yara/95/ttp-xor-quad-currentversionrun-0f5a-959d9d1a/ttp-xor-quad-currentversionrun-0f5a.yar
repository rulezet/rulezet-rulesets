rule TTP_XOR_QUAD_CurrentVersionRun_0f5a {
  strings:
    $key_0f5a = { 5c 35 [2] 78 3b [2] 53 17 [2] 7d 35 [2] 69 2e [2] 66 34 [2] 78 29 [2] 7a 28 [2] 61 2e [2] 7d 29 [2] 61 06 }

  condition:
    any of them
}