rule TTP_XOR_QUAD_CurrentVersionRun_fb00 {
  strings:
    $key_fb00 = { a8 6f [2] 8c 61 [2] a7 4d [2] 89 6f [2] 9d 74 [2] 92 6e [2] 8c 73 [2] 8e 72 [2] 95 74 [2] 89 73 [2] 95 5c }

  condition:
    any of them
}