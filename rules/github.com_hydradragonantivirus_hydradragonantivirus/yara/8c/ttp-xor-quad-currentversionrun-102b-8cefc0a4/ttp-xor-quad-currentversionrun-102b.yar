rule TTP_XOR_QUAD_CurrentVersionRun_102b {
  strings:
    $key_102b = { 43 44 [2] 67 4a [2] 4c 66 [2] 62 44 [2] 76 5f [2] 79 45 [2] 67 58 [2] 65 59 [2] 7e 5f [2] 62 58 [2] 7e 77 }

  condition:
    any of them
}