rule TTP_XOR_QUAD_CurrentVersionRun_3a5a {
  strings:
    $key_3a5a = { 69 35 [2] 4d 3b [2] 66 17 [2] 48 35 [2] 5c 2e [2] 53 34 [2] 4d 29 [2] 4f 28 [2] 54 2e [2] 48 29 [2] 54 06 }

  condition:
    any of them
}