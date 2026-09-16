rule TTP_XOR_QUAD_CurrentVersionRun_4e30 {
  strings:
    $key_4e30 = { 1d 5f [2] 39 51 [2] 12 7d [2] 3c 5f [2] 28 44 [2] 27 5e [2] 39 43 [2] 3b 42 [2] 20 44 [2] 3c 43 [2] 20 6c }

  condition:
    any of them
}