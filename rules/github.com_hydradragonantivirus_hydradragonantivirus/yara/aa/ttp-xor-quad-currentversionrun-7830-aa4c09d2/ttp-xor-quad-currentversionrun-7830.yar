rule TTP_XOR_QUAD_CurrentVersionRun_7830 {
  strings:
    $key_7830 = { 2b 5f [2] 0f 51 [2] 24 7d [2] 0a 5f [2] 1e 44 [2] 11 5e [2] 0f 43 [2] 0d 42 [2] 16 44 [2] 0a 43 [2] 16 6c }

  condition:
    any of them
}