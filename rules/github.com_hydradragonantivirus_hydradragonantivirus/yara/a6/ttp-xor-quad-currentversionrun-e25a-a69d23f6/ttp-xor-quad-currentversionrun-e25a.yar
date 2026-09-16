rule TTP_XOR_QUAD_CurrentVersionRun_e25a {
  strings:
    $key_e25a = { b1 35 [2] 95 3b [2] be 17 [2] 90 35 [2] 84 2e [2] 8b 34 [2] 95 29 [2] 97 28 [2] 8c 2e [2] 90 29 [2] 8c 06 }

  condition:
    any of them
}