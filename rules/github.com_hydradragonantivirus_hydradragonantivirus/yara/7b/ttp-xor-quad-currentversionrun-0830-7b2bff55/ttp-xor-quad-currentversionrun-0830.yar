rule TTP_XOR_QUAD_CurrentVersionRun_0830 {
  strings:
    $key_0830 = { 5b 5f [2] 7f 51 [2] 54 7d [2] 7a 5f [2] 6e 44 [2] 61 5e [2] 7f 43 [2] 7d 42 [2] 66 44 [2] 7a 43 [2] 66 6c }

  condition:
    any of them
}