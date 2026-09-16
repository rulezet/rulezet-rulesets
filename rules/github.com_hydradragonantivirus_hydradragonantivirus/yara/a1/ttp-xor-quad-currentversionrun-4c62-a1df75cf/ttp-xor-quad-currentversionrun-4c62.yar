rule TTP_XOR_QUAD_CurrentVersionRun_4c62 {
  strings:
    $key_4c62 = { 1f 0d [2] 3b 03 [2] 10 2f [2] 3e 0d [2] 2a 16 [2] 25 0c [2] 3b 11 [2] 39 10 [2] 22 16 [2] 3e 11 [2] 22 3e }

  condition:
    any of them
}