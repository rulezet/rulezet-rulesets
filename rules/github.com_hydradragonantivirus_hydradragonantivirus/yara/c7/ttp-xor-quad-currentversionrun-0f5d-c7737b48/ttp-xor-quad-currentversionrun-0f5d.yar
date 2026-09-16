rule TTP_XOR_QUAD_CurrentVersionRun_0f5d {
  strings:
    $key_0f5d = { 5c 32 [2] 78 3c [2] 53 10 [2] 7d 32 [2] 69 29 [2] 66 33 [2] 78 2e [2] 7a 2f [2] 61 29 [2] 7d 2e [2] 61 01 }

  condition:
    any of them
}