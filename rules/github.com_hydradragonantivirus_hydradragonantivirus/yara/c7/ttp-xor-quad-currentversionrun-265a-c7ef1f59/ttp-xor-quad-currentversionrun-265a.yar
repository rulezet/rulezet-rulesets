rule TTP_XOR_QUAD_CurrentVersionRun_265a {
  strings:
    $key_265a = { 75 35 [2] 51 3b [2] 7a 17 [2] 54 35 [2] 40 2e [2] 4f 34 [2] 51 29 [2] 53 28 [2] 48 2e [2] 54 29 [2] 48 06 }

  condition:
    any of them
}