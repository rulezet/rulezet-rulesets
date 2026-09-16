rule TTP_XOR_QUAD_CurrentVersionRun_310c {
  strings:
    $key_310c = { 62 63 [2] 46 6d [2] 6d 41 [2] 43 63 [2] 57 78 [2] 58 62 [2] 46 7f [2] 44 7e [2] 5f 78 [2] 43 7f [2] 5f 50 }

  condition:
    any of them
}