rule TTP_XOR_QUAD_CurrentVersionRun_311d {
  strings:
    $key_311d = { 62 72 [2] 46 7c [2] 6d 50 [2] 43 72 [2] 57 69 [2] 58 73 [2] 46 6e [2] 44 6f [2] 5f 69 [2] 43 6e [2] 5f 41 }

  condition:
    any of them
}