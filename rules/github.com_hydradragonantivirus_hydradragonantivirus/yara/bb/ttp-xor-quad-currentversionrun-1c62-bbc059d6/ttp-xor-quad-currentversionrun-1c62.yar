rule TTP_XOR_QUAD_CurrentVersionRun_1c62 {
  strings:
    $key_1c62 = { 4f 0d [2] 6b 03 [2] 40 2f [2] 6e 0d [2] 7a 16 [2] 75 0c [2] 6b 11 [2] 69 10 [2] 72 16 [2] 6e 11 [2] 72 3e }

  condition:
    any of them
}