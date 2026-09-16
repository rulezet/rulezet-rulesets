rule TTP_XOR_QUAD_CurrentVersionRun_0f40 {
  strings:
    $key_0f40 = { 5c 2f [2] 78 21 [2] 53 0d [2] 7d 2f [2] 69 34 [2] 66 2e [2] 78 33 [2] 7a 32 [2] 61 34 [2] 7d 33 [2] 61 1c }

  condition:
    any of them
}