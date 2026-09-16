rule TTP_XOR_QUAD_CurrentVersionRun_7e2b {
  strings:
    $key_7e2b = { 2d 44 [2] 09 4a [2] 22 66 [2] 0c 44 [2] 18 5f [2] 17 45 [2] 09 58 [2] 0b 59 [2] 10 5f [2] 0c 58 [2] 10 77 }

  condition:
    any of them
}