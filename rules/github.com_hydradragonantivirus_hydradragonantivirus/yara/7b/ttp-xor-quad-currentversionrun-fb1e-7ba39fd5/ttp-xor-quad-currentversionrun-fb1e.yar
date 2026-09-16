rule TTP_XOR_QUAD_CurrentVersionRun_fb1e {
  strings:
    $key_fb1e = { a8 71 [2] 8c 7f [2] a7 53 [2] 89 71 [2] 9d 6a [2] 92 70 [2] 8c 6d [2] 8e 6c [2] 95 6a [2] 89 6d [2] 95 42 }

  condition:
    any of them
}