rule TTP_XOR_QUAD_CurrentVersionRun_082b {
  strings:
    $key_082b = { 5b 44 [2] 7f 4a [2] 54 66 [2] 7a 44 [2] 6e 5f [2] 61 45 [2] 7f 58 [2] 7d 59 [2] 66 5f [2] 7a 58 [2] 66 77 }

  condition:
    any of them
}