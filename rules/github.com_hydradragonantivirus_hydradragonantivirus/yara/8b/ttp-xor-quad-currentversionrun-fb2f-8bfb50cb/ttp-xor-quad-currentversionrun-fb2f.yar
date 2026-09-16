rule TTP_XOR_QUAD_CurrentVersionRun_fb2f {
  strings:
    $key_fb2f = { a8 40 [2] 8c 4e [2] a7 62 [2] 89 40 [2] 9d 5b [2] 92 41 [2] 8c 5c [2] 8e 5d [2] 95 5b [2] 89 5c [2] 95 73 }

  condition:
    any of them
}