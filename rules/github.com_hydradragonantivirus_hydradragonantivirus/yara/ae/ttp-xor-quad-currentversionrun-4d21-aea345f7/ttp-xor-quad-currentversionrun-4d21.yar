rule TTP_XOR_QUAD_CurrentVersionRun_4d21 {
  strings:
    $key_4d21 = { 1e 4e [2] 3a 40 [2] 11 6c [2] 3f 4e [2] 2b 55 [2] 24 4f [2] 3a 52 [2] 38 53 [2] 23 55 [2] 3f 52 [2] 23 7d }

  condition:
    any of them
}