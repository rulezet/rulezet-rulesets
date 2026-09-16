rule TTP_XOR_QUAD_CurrentVersionRun_6c2b {
  strings:
    $key_6c2b = { 3f 44 [2] 1b 4a [2] 30 66 [2] 1e 44 [2] 0a 5f [2] 05 45 [2] 1b 58 [2] 19 59 [2] 02 5f [2] 1e 58 [2] 02 77 }

  condition:
    any of them
}