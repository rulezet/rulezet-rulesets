rule TTP_XOR_QUAD_CurrentVersionRun_316d {
  strings:
    $key_316d = { 62 02 [2] 46 0c [2] 6d 20 [2] 43 02 [2] 57 19 [2] 58 03 [2] 46 1e [2] 44 1f [2] 5f 19 [2] 43 1e [2] 5f 31 }

  condition:
    any of them
}