rule TTP_XOR_QUAD_CurrentVersionRun_fb3c {
  strings:
    $key_fb3c = { a8 53 [2] 8c 5d [2] a7 71 [2] 89 53 [2] 9d 48 [2] 92 52 [2] 8c 4f [2] 8e 4e [2] 95 48 [2] 89 4f [2] 95 60 }

  condition:
    any of them
}