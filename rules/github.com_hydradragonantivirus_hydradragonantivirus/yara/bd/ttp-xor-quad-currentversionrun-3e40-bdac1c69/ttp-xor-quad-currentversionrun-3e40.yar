rule TTP_XOR_QUAD_CurrentVersionRun_3e40 {
  strings:
    $key_3e40 = { 6d 2f [2] 49 21 [2] 62 0d [2] 4c 2f [2] 58 34 [2] 57 2e [2] 49 33 [2] 4b 32 [2] 50 34 [2] 4c 33 [2] 50 1c }

  condition:
    any of them
}