rule TTP_XOR_QUAD_CurrentVersionRun_fb30 {
  strings:
    $key_fb30 = { a8 5f [2] 8c 51 [2] a7 7d [2] 89 5f [2] 9d 44 [2] 92 5e [2] 8c 43 [2] 8e 42 [2] 95 44 [2] 89 43 [2] 95 6c }

  condition:
    any of them
}