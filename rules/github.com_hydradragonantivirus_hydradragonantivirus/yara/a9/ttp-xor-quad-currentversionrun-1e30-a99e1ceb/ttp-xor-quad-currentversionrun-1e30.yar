rule TTP_XOR_QUAD_CurrentVersionRun_1e30 {
  strings:
    $key_1e30 = { 4d 5f [2] 69 51 [2] 42 7d [2] 6c 5f [2] 78 44 [2] 77 5e [2] 69 43 [2] 6b 42 [2] 70 44 [2] 6c 43 [2] 70 6c }

  condition:
    any of them
}