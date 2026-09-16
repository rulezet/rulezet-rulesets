rule TTP_XOR_QUAD_CurrentVersionRun_235a {
  strings:
    $key_235a = { 70 35 [2] 54 3b [2] 7f 17 [2] 51 35 [2] 45 2e [2] 4a 34 [2] 54 29 [2] 56 28 [2] 4d 2e [2] 51 29 [2] 4d 06 }

  condition:
    any of them
}