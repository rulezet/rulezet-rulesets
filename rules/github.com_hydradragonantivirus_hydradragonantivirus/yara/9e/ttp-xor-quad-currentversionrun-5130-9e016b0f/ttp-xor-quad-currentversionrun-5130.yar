rule TTP_XOR_QUAD_CurrentVersionRun_5130 {
  strings:
    $key_5130 = { 02 5f [2] 26 51 [2] 0d 7d [2] 23 5f [2] 37 44 [2] 38 5e [2] 26 43 [2] 24 42 [2] 3f 44 [2] 23 43 [2] 3f 6c }

  condition:
    any of them
}