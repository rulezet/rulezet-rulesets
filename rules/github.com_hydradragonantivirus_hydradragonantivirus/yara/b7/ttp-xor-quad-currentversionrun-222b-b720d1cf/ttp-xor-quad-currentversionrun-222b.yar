rule TTP_XOR_QUAD_CurrentVersionRun_222b {
  strings:
    $key_222b = { 71 44 [2] 55 4a [2] 7e 66 [2] 50 44 [2] 44 5f [2] 4b 45 [2] 55 58 [2] 57 59 [2] 4c 5f [2] 50 58 [2] 4c 77 }

  condition:
    any of them
}