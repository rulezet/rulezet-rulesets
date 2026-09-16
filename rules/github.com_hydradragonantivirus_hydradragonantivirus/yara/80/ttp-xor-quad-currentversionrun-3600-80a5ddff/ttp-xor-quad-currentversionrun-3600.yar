rule TTP_XOR_QUAD_CurrentVersionRun_3600 {
  strings:
    $key_3600 = { 65 6f [2] 41 61 [2] 6a 4d [2] 44 6f [2] 50 74 [2] 5f 6e [2] 41 73 [2] 43 72 [2] 58 74 [2] 44 73 [2] 58 5c }

  condition:
    any of them
}