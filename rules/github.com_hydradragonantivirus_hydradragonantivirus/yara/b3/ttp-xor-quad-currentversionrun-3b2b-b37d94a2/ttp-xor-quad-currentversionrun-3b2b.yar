rule TTP_XOR_QUAD_CurrentVersionRun_3b2b {
  strings:
    $key_3b2b = { 68 44 [2] 4c 4a [2] 67 66 [2] 49 44 [2] 5d 5f [2] 52 45 [2] 4c 58 [2] 4e 59 [2] 55 5f [2] 49 58 [2] 55 77 }

  condition:
    any of them
}