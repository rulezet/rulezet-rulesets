rule TTP_XOR_QUAD_CurrentVersionRun_2b2b {
  strings:
    $key_2b2b = { 78 44 [2] 5c 4a [2] 77 66 [2] 59 44 [2] 4d 5f [2] 42 45 [2] 5c 58 [2] 5e 59 [2] 45 5f [2] 59 58 [2] 45 77 }

  condition:
    any of them
}